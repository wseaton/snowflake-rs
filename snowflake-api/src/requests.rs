use std::collections::HashMap;

use serde::Serialize;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExecRequest {
    pub sql_text: String,
    pub async_exec: bool,
    pub sequence_id: u64,
    pub is_internal: bool,
    /// When true, Snowflake parses + validates + returns schema metadata
    /// without executing. Skipped from the wire when false to keep normal
    /// requests untouched.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub describe_only: bool,
    /// Positional bindings for `?` placeholders. Keys are 1-indexed string
    /// positions ("1", "2", ...) per Snowflake's internal API. `None` is
    /// serialized as omitted so unbound queries don't send the field at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindings: Option<HashMap<String, BindParam>>,
    /// Per-statement parameters injected into the request body. Used today
    /// for `MULTI_STATEMENT_COUNT`; gosnowflake's `parameters` field on the
    /// same endpoint takes any session-level parameter name as a key.
    /// Empty -> omitted from the wire.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub parameters: HashMap<String, serde_json::Value>,
}

/// One positional bind parameter on the wire. The Snowflake type name goes in
/// `type_` (TEXT, FIXED, REAL, BOOLEAN, ...); the value is JSON, but in
/// practice almost always a stringified primitive.
#[derive(Serialize, Debug, Clone)]
pub struct BindParam {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub value: serde_json::Value,
}

/// A typed bind value. Construct via the inherent constructors
/// (`Bind::text`, `Bind::fixed`, etc.) or via `Into` from common primitive
/// types. Pass a slice of these to the query builder.
#[derive(Debug, Clone)]
pub struct Bind(pub(crate) BindParam);

impl Bind {
    /// VARCHAR / TEXT / STRING.
    pub fn text(s: impl Into<String>) -> Self {
        Self(BindParam {
            type_: "TEXT",
            value: serde_json::Value::String(s.into()),
        })
    }

    /// Integer (NUMBER with scale 0). Snowflake expects FIXED values as
    /// strings to preserve full 38-digit precision through JSON.
    pub fn fixed(n: i64) -> Self {
        Self(BindParam {
            type_: "FIXED",
            value: serde_json::Value::String(n.to_string()),
        })
    }

    /// Floating-point (NUMBER / FLOAT / DOUBLE).
    pub fn real(f: f64) -> Self {
        Self(BindParam {
            type_: "REAL",
            value: serde_json::Value::String(f.to_string()),
        })
    }

    /// BOOLEAN.
    pub fn boolean(b: bool) -> Self {
        Self(BindParam {
            type_: "BOOLEAN",
            value: serde_json::Value::String(b.to_string()),
        })
    }

    /// SQL NULL with a type hint. The type matters because Snowflake's
    /// type inference happens at bind time; a mistyped NULL can change
    /// query semantics.
    pub fn null(type_: &'static str) -> Self {
        Self(BindParam {
            type_,
            value: serde_json::Value::Null,
        })
    }
}

impl From<&str> for Bind {
    fn from(s: &str) -> Self {
        Bind::text(s)
    }
}
impl From<String> for Bind {
    fn from(s: String) -> Self {
        Bind::text(s)
    }
}
impl From<i32> for Bind {
    fn from(n: i32) -> Self {
        Bind::fixed(i64::from(n))
    }
}
impl From<i64> for Bind {
    fn from(n: i64) -> Self {
        Bind::fixed(n)
    }
}
impl From<u32> for Bind {
    fn from(n: u32) -> Self {
        Bind::fixed(i64::from(n))
    }
}
impl From<f32> for Bind {
    fn from(f: f32) -> Self {
        Bind::real(f64::from(f))
    }
}
impl From<f64> for Bind {
    fn from(f: f64) -> Self {
        Bind::real(f)
    }
}
impl From<bool> for Bind {
    fn from(b: bool) -> Self {
        Bind::boolean(b)
    }
}

/// Body for `/queries/v1/abort-request`. The `request_id` is the UUID generated
/// for the original query POST (the one we want to cancel), serialized as
/// `requestId`. The cancel POST itself carries its own `request_id`/`request_guid`
/// in URL params.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AbortRequest {
    pub request_id: String,
}

#[derive(Serialize, Debug)]
pub struct LoginRequest<T> {
    pub data: T,
}

pub type PasswordLoginRequest = LoginRequest<PasswordRequestData>;
#[cfg(feature = "cert-auth")]
pub type CertLoginRequest = LoginRequest<CertRequestData>;
#[cfg(feature = "browser-auth")]
pub type BrowserLoginRequest = LoginRequest<BrowserRequestData>;
pub type OAuthLoginRequest = LoginRequest<OAuthRequestData>;

#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct LoginRequestCommon {
    pub client_app_id: String,
    pub client_app_version: String,
    pub svn_revision: String,
    pub account_name: String,
    pub login_name: String,
    pub session_parameters: SessionParameters,
    pub client_environment: ClientEnvironment,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct SessionParameters {
    pub client_validate_default_parameters: bool,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct ClientEnvironment {
    pub application: String,
    pub os: String,
    pub os_version: String,
    pub ocsp_mode: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct PasswordRequestData {
    #[serde(flatten)]
    pub login_request_common: LoginRequestCommon,
    pub password: String,
}

#[cfg(feature = "cert-auth")]
#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CertRequestData {
    #[serde(flatten)]
    pub login_request_common: LoginRequestCommon,
    pub authenticator: String,
    pub token: String,
}

/// Login body for OAuth. Snowflake's REST login accepts `AUTHENTICATOR: OAUTH`
/// with the access token in `TOKEN`; the `LOGIN_NAME` in `login_request_common`
/// still has to match the Snowflake user the token was issued for.
#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct OAuthRequestData {
    #[serde(flatten)]
    pub login_request_common: LoginRequestCommon,
    pub authenticator: String,
    pub token: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RenewSessionRequest {
    pub old_session_token: String,
    pub request_type: String,
}

/// Request for the first phase of browser SSO authentication.
/// Sent to /session/authenticator-request to get the SSO URL.
#[cfg(feature = "browser-auth")]
#[derive(Serialize, Debug)]
pub struct AuthenticatorRequest {
    pub data: AuthenticatorRequestData,
}

#[cfg(feature = "browser-auth")]
#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct AuthenticatorRequestData {
    pub client_app_id: String,
    pub client_app_version: String,
    pub svn_revision: String,
    pub account_name: String,
    pub login_name: String,
    pub authenticator: String,
    /// Port for the local callback listener
    pub browser_mode_redirect_port: String,
    /// Proof key for the SSO challenge
    pub proof_key: String,
    pub client_environment: AuthenticatorClientEnvironment,
}

#[cfg(feature = "browser-auth")]
#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct AuthenticatorClientEnvironment {
    pub application: String,
    pub os: String,
    pub os_version: String,
}

/// Request data for the second phase of browser SSO authentication.
/// Sent to /session/v1/login-request with the token from the browser callback.
#[cfg(feature = "browser-auth")]
#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct BrowserRequestData {
    #[serde(flatten)]
    pub login_request_common: LoginRequestCommon,
    pub authenticator: String,
    pub token: String,
    pub proof_key: String,
}
