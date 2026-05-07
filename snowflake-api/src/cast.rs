//! Rebuild Utf8-with-JSON columns into native Arrow `Map` / `List`
//! types. Opt-in entry: [`cast_structured_batch`].

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, Float64Builder, Int64Builder, ListBuilder, MapBuilder, StringBuilder,
};
use arrow_array::{Array, ArrayRef, RecordBatch, StringArray};
use arrow_schema::{ArrowError, DataType, Field, Schema};
use serde_json::Value;

const LOGICAL_TYPE: &str = "logicalType";
/// Set on Arrow field metadata for `GEOGRAPHY` / `GEOMETRY` columns;
/// the cast skips them so callers get raw `GeoJSON` instead of a
/// shredded `Map<Utf8, Utf8>`.
pub(crate) const SF_EXT_TYPE: &str = "snowflakeExtType";

/// Rewrite Utf8 columns whose Arrow field metadata carries
/// `logicalType: "OBJECT"` or `"ARRAY"` into proper Arrow
/// `Map<Utf8, V>` / `List<E>`. `V` and `E` are inferred per-batch
/// (`Boolean` / `Int64` / `Float64` / `Utf8`).
///
/// Skipped:
/// * `VARIANT` columns (free-form by row, no useful single Arrow type)
/// * Columns whose `snowflakeExtType` metadata is `GEOGRAPHY` /
///   `GEOMETRY` — `GeoJSON` is one semantic unit, callers want it raw.
/// * Anything that isn't physically Utf8.
pub fn cast_structured_batch(batch: &RecordBatch) -> Result<RecordBatch, ArrowError> {
    cast_structured_batch_with_schema(batch, &[])
}

/// Like [`cast_structured_batch`], but `column_schema` (the Snowflake
/// rowtype carried on [`crate::QueryMetadata::column_schema`]) supplies
/// `ext_type_name` info that isn't in the Arrow field metadata yet.
/// Use this on the streaming path so `GEOGRAPHY` / `GEOMETRY` columns
/// stay as raw `Utf8` `GeoJSON` instead of being shredded into
/// `Map<Utf8, Utf8>`.
///
/// Single-pass: classify each column, fast-return the original batch
/// if every column is pass-through, otherwise rebuild the schema once
/// with `Arc::clone` for unchanged fields and a fresh `Field` only
/// for ones that actually changed.
pub fn cast_structured_batch_with_schema(
    batch: &RecordBatch,
    column_schema: &[crate::FieldSchema],
) -> Result<RecordBatch, ArrowError> {
    let actions: Vec<Action> = batch
        .schema()
        .fields()
        .iter()
        .enumerate()
        .map(|(i, field)| classify(i, field, column_schema))
        .collect();

    if actions.iter().all(|a| matches!(a, Action::Passthrough)) {
        return Ok(batch.clone());
    }

    let mut new_fields: Vec<Arc<Field>> = Vec::with_capacity(batch.num_columns());
    let mut new_columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns());

    for (i, field) in batch.schema().fields().iter().enumerate() {
        match &actions[i] {
            Action::Passthrough => {
                new_fields.push(Arc::clone(field));
                new_columns.push(Arc::clone(batch.column(i)));
            }
            Action::Annotate(ext) => {
                let mut md = field.metadata().clone();
                md.insert(SF_EXT_TYPE.to_owned(), ext.clone());
                new_fields.push(Arc::new(
                    Field::new(field.name(), field.data_type().clone(), field.is_nullable())
                        .with_metadata(md),
                ));
                new_columns.push(Arc::clone(batch.column(i)));
            }
            Action::CastObject => {
                let arr = downcast_str(batch.column(i))?;
                let casted = cast_object_column(arr)?;
                new_fields.push(rewrap(field, &casted));
                new_columns.push(casted);
            }
            Action::CastArray => {
                let arr = downcast_str(batch.column(i))?;
                let casted = cast_array_column(arr)?;
                new_fields.push(rewrap(field, &casted));
                new_columns.push(casted);
            }
        }
    }

    let new_schema = Arc::new(Schema::new_with_metadata(
        new_fields,
        batch.schema().metadata().clone(),
    ));
    RecordBatch::try_new(new_schema, new_columns)
}

enum Action {
    Passthrough,
    /// Stamp `SF_EXT_TYPE` onto field metadata; column data unchanged.
    Annotate(String),
    CastObject,
    CastArray,
}

fn classify(i: usize, field: &Arc<Field>, column_schema: &[crate::FieldSchema]) -> Action {
    let logical = field.metadata().get(LOGICAL_TYPE).map(String::as_str);
    let md_ext = field.metadata().get(SF_EXT_TYPE).map(String::as_str);
    let schema_ext = column_schema
        .get(i)
        .and_then(|fs| fs.ext_type_name.as_deref());
    let ext = md_ext.or(schema_ext);
    let geo = matches!(ext, Some("GEOGRAPHY" | "GEOMETRY"));
    let castable_utf8 = field.data_type() == &DataType::Utf8;

    match (logical, castable_utf8, geo) {
        (Some("OBJECT"), true, false) => Action::CastObject,
        (Some("ARRAY"), true, false) => Action::CastArray,
        // No cast, but we have an ext_type_name from the schema that
        // isn't yet on the field metadata — stamp it so downstream
        // consumers can see it.
        _ if md_ext.is_none() => match schema_ext {
            Some(s) => Action::Annotate(s.to_owned()),
            None => Action::Passthrough,
        },
        _ => Action::Passthrough,
    }
}

fn downcast_str(col: &ArrayRef) -> Result<&StringArray, ArrowError> {
    col.as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| ArrowError::CastError("expected StringArray".into()))
}

fn rewrap(field: &Arc<Field>, casted: &ArrayRef) -> Arc<Field> {
    Arc::new(
        Field::new(
            field.name(),
            casted.data_type().clone(),
            field.is_nullable(),
        )
        .with_metadata(field.metadata().clone()),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scalar {
    Boolean,
    Int64,
    Float64,
    Utf8,
}

fn infer_scalar<'a>(values: impl Iterator<Item = &'a Value>) -> Scalar {
    let mut all_bool = true;
    let mut all_int = true;
    let mut all_num = true;

    for v in values {
        match v {
            Value::Null => {}
            Value::Bool(_) => {
                all_int = false;
                all_num = false;
            }
            Value::Number(n) if n.is_i64() => {
                all_bool = false;
            }
            Value::Number(_) => {
                all_bool = false;
                all_int = false;
            }
            Value::String(_) | Value::Array(_) | Value::Object(_) => {
                all_bool = false;
                all_int = false;
                all_num = false;
            }
        }
    }

    if all_bool {
        Scalar::Boolean
    } else if all_int {
        Scalar::Int64
    } else if all_num {
        Scalar::Float64
    } else {
        Scalar::Utf8
    }
}

fn cast_object_column(arr: &StringArray) -> Result<ArrayRef, ArrowError> {
    let mut parsed: Vec<Option<serde_json::Map<String, Value>>> = Vec::with_capacity(arr.len());
    for i in 0..arr.len() {
        if arr.is_null(i) {
            parsed.push(None);
            continue;
        }
        let s = arr.value(i);
        let v: Value = serde_json::from_str(s).map_err(|e| {
            ArrowError::ExternalError(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("OBJECT column row {i} not valid JSON: {e}"),
            )))
        })?;
        match v {
            Value::Null => parsed.push(None),
            Value::Object(m) => parsed.push(Some(m)),
            other => {
                return Err(ArrowError::CastError(format!(
                    "OBJECT column row {i} expected JSON object, got {}",
                    short_kind(&other)
                )));
            }
        }
    }

    let value_type = infer_scalar(parsed.iter().flatten().flat_map(|m| m.values()));

    let key_b = StringBuilder::new();
    macro_rules! build_map {
        ($vb:expr) => {{
            let mut mb = MapBuilder::new(None, key_b, $vb);
            for entry in &parsed {
                match entry {
                    None => mb.append(false)?,
                    Some(m) => {
                        for (k, v) in m {
                            mb.keys().append_value(k);
                            append_value_into(value_type, v, mb.values());
                        }
                        mb.append(true)?;
                    }
                }
            }
            let arr = mb.finish();
            Arc::new(arr) as ArrayRef
        }};
    }

    let out: ArrayRef = match value_type {
        Scalar::Boolean => build_map!(BooleanBuilder::new()),
        Scalar::Int64 => build_map!(Int64Builder::new()),
        Scalar::Float64 => build_map!(Float64Builder::new()),
        Scalar::Utf8 => build_map!(StringBuilder::new()),
    };
    Ok(out)
}

fn cast_array_column(arr: &StringArray) -> Result<ArrayRef, ArrowError> {
    let mut parsed: Vec<Option<Vec<Value>>> = Vec::with_capacity(arr.len());
    for i in 0..arr.len() {
        if arr.is_null(i) {
            parsed.push(None);
            continue;
        }
        let s = arr.value(i);
        let v: Value = serde_json::from_str(s).map_err(|e| {
            ArrowError::ExternalError(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ARRAY column row {i} not valid JSON: {e}"),
            )))
        })?;
        match v {
            Value::Null => parsed.push(None),
            Value::Array(a) => parsed.push(Some(a)),
            other => {
                return Err(ArrowError::CastError(format!(
                    "ARRAY column row {i} expected JSON array, got {}",
                    short_kind(&other)
                )));
            }
        }
    }

    let elem_type = infer_scalar(parsed.iter().flatten().flat_map(|a| a.iter()));

    macro_rules! build_list {
        ($eb:expr) => {{
            let mut lb = ListBuilder::new($eb);
            for entry in &parsed {
                match entry {
                    None => lb.append(false),
                    Some(a) => {
                        for v in a {
                            append_value_into(elem_type, v, lb.values());
                        }
                        lb.append(true);
                    }
                }
            }
            let arr = lb.finish();
            Arc::new(arr) as ArrayRef
        }};
    }

    let out: ArrayRef = match elem_type {
        Scalar::Boolean => build_list!(BooleanBuilder::new()),
        Scalar::Int64 => build_list!(Int64Builder::new()),
        Scalar::Float64 => build_list!(Float64Builder::new()),
        Scalar::Utf8 => build_list!(StringBuilder::new()),
    };
    Ok(out)
}

fn append_value_into(target: Scalar, v: &Value, builder: &mut dyn std::any::Any) {
    match target {
        Scalar::Boolean => {
            let b = builder.downcast_mut::<BooleanBuilder>().expect("Boolean");
            match v {
                Value::Bool(x) => b.append_value(*x),
                _ => b.append_null(),
            }
        }
        Scalar::Int64 => {
            let b = builder.downcast_mut::<Int64Builder>().expect("Int64");
            match v {
                Value::Number(n) => match n.as_i64() {
                    Some(i) => b.append_value(i),
                    None => b.append_null(),
                },
                _ => b.append_null(),
            }
        }
        Scalar::Float64 => {
            let b = builder.downcast_mut::<Float64Builder>().expect("Float64");
            match v {
                Value::Number(n) => match n.as_f64() {
                    Some(f) => b.append_value(f),
                    None => b.append_null(),
                },
                _ => b.append_null(),
            }
        }
        Scalar::Utf8 => {
            let b = builder.downcast_mut::<StringBuilder>().expect("Utf8");
            match v {
                Value::Null => b.append_null(),
                Value::String(s) => b.append_value(s),
                other => {
                    let s = serde_json::to_string(other).unwrap_or_default();
                    b.append_value(s);
                }
            }
        }
    }
}

fn short_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::cast::AsArray;
    use arrow_array::types::Int64Type;
    use std::collections::HashMap;

    fn batch_with_metadata(name: &str, md: HashMap<String, String>, rows: &[&str]) -> RecordBatch {
        let arr = StringArray::from(rows.to_vec());
        let f = Arc::new(Field::new(name, DataType::Utf8, true).with_metadata(md));
        let schema = Arc::new(Schema::new(vec![f]));
        RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap()
    }

    fn batch_with_logical(name: &str, logical: &str, rows: &[&str]) -> RecordBatch {
        let mut md = HashMap::new();
        md.insert(LOGICAL_TYPE.to_owned(), logical.to_owned());
        batch_with_metadata(name, md, rows)
    }

    #[test]
    fn object_with_string_values_becomes_map_utf8_utf8() {
        let b = batch_with_logical("m", "OBJECT", &[r#"{"a":"x","b":"y"}"#, r#"{"c":"z"}"#]);
        let out = cast_structured_batch(&b).unwrap();
        match out.schema().field(0).data_type() {
            DataType::Map(field, _) => {
                if let DataType::Struct(fields) = field.data_type() {
                    assert_eq!(fields[0].data_type(), &DataType::Utf8);
                    assert_eq!(fields[1].data_type(), &DataType::Utf8);
                } else {
                    panic!();
                }
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn object_with_int_values_becomes_map_utf8_int64() {
        let b = batch_with_logical("m", "OBJECT", &[r#"{"a":1,"b":2}"#, r#"{"c":3}"#]);
        let out = cast_structured_batch(&b).unwrap();
        match out.schema().field(0).data_type() {
            DataType::Map(field, _) => {
                if let DataType::Struct(fields) = field.data_type() {
                    assert_eq!(fields[1].data_type(), &DataType::Int64);
                } else {
                    panic!();
                }
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn array_of_ints_becomes_list_int64() {
        let b = batch_with_logical("a", "ARRAY", &["[1,2,3]", "[4,5]"]);
        let out = cast_structured_batch(&b).unwrap();
        match out.schema().field(0).data_type() {
            DataType::List(field) => assert_eq!(field.data_type(), &DataType::Int64),
            other => panic!("expected List, got {other:?}"),
        }
        let list = out.column(0).as_list::<i32>();
        let ints = list.value(0).as_primitive::<Int64Type>().clone();
        assert_eq!(ints.values(), &[1, 2, 3]);
    }

    #[test]
    fn array_of_mixed_types_falls_back_to_list_utf8() {
        let b = batch_with_logical("a", "ARRAY", &[r#"[1,"two",true]"#]);
        let out = cast_structured_batch(&b).unwrap();
        match out.schema().field(0).data_type() {
            DataType::List(field) => assert_eq!(field.data_type(), &DataType::Utf8),
            other => panic!("expected List<Utf8>, got {other:?}"),
        }
    }

    #[test]
    fn variant_column_left_alone() {
        let b = batch_with_logical("v", "VARIANT", &[r#"{"foo":"bar"}"#]);
        let out = cast_structured_batch(&b).unwrap();
        assert_eq!(out.schema().field(0).data_type(), &DataType::Utf8);
    }

    #[test]
    fn geography_column_left_as_utf8() {
        let mut md = HashMap::new();
        md.insert(LOGICAL_TYPE.to_owned(), "OBJECT".to_owned());
        md.insert(SF_EXT_TYPE.to_owned(), "GEOGRAPHY".to_owned());
        let b = batch_with_metadata("g", md, &[r#"{"type":"Point","coordinates":[0,0]}"#]);
        let out = cast_structured_batch(&b).unwrap();
        assert_eq!(out.schema().field(0).data_type(), &DataType::Utf8);
    }

    #[test]
    fn non_structured_column_pass_through() {
        let arr = StringArray::from(vec!["hello", "world"]);
        let f = Arc::new(Field::new("name", DataType::Utf8, true));
        let schema = Arc::new(Schema::new(vec![f]));
        let b = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let out = cast_structured_batch(&b).unwrap();
        assert_eq!(out.schema().field(0).data_type(), &DataType::Utf8);
    }
}
