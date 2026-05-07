//! retry middleware that rotates per-attempt url parameters.
//!
//! on every attempt, `request_guid` is set to a fresh uuidv4. on retry
//! attempts of `/queries/v1/query-request`, `retryCount`, `retryReason`,
//! and `clientStartTime` (captured once before the loop) are also written.
//! `requestId` is set by the caller and never touched here.
//!
//! non-snowflake hosts get retries with no parameter injection so we don't
//! invalidate presigned chunk-download urls.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Error, Middleware, Next, Result};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::{
    DefaultRetryableStrategy, RetryDecision, RetryPolicy, Retryable, RetryableStrategy,
};
use url::Url;
use uuid::Uuid;

const REQUEST_GUID_KEY: &str = "request_guid";
const RETRY_COUNT_KEY: &str = "retryCount";
const RETRY_REASON_KEY: &str = "retryReason";
const CLIENT_START_TIME_KEY: &str = "clientStartTime";
const QUERY_REQUEST_PATH: &str = "/queries/v1/query-request";

pub struct SnowflakeRetryMiddleware {
    retry_policy: ExponentialBackoff,
}

impl SnowflakeRetryMiddleware {
    pub fn new(retry_policy: ExponentialBackoff) -> Self {
        Self { retry_policy }
    }
}

#[async_trait::async_trait]
impl Middleware for SnowflakeRetryMiddleware {
    async fn handle(&self, req: Request, ext: &mut Extensions, next: Next<'_>) -> Result<Response> {
        let client_start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let start_time = SystemTime::now();

        let mut n_past_retries: u32 = 0;
        let mut last_status: Option<u16> = None;

        loop {
            let mut attempt = req
                .try_clone()
                .ok_or_else(|| Error::middleware(NonCloneableRequest))?;

            if is_snowflake_host(attempt.url()) {
                let is_query_request = attempt.url().path() == QUERY_REQUEST_PATH;
                let url = attempt.url_mut();
                set_query_param(url, REQUEST_GUID_KEY, &Uuid::new_v4().to_string());
                if n_past_retries > 0 && is_query_request {
                    set_query_param(url, RETRY_COUNT_KEY, &n_past_retries.to_string());
                    set_query_param(url, RETRY_REASON_KEY, &last_status.unwrap_or(0).to_string());
                    ensure_query_param(url, CLIENT_START_TIME_KEY, &client_start_time);
                }
            }

            let result = next.clone().run(attempt, ext).await;

            if matches!(
                DefaultRetryableStrategy.handle(&result),
                Some(Retryable::Transient)
            ) {
                if let RetryDecision::Retry { execute_after } =
                    self.retry_policy.should_retry(start_time, n_past_retries)
                {
                    last_status = match &result {
                        Ok(resp) => Some(resp.status().as_u16()),
                        Err(_) => None,
                    };
                    drop(result);
                    let duration = execute_after
                        .duration_since(SystemTime::now())
                        .unwrap_or_else(|_| Duration::default());
                    log::debug!(
                        "snowflake retry attempt {} sleeping {:?} (last_status={:?})",
                        n_past_retries + 1,
                        duration,
                        last_status
                    );
                    tokio::time::sleep(duration).await;
                    n_past_retries = n_past_retries.saturating_add(1);
                    continue;
                }
            }

            return result;
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("request object is not cloneable. are you passing a streaming body?")]
struct NonCloneableRequest;

fn set_query_param(url: &mut Url, key: &str, value: &str) {
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != key)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(kept.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .append_pair(key, value);
}

fn ensure_query_param(url: &mut Url, key: &str, value: &str) {
    if !url.query_pairs().any(|(k, _)| k == key) {
        url.query_pairs_mut().append_pair(key, value);
    }
}

fn is_snowflake_host(url: &Url) -> bool {
    url.host_str().is_some_and(|h| {
        h.ends_with(".snowflakecomputing.com")
            || h.ends_with(".snowflakecomputing.cn")
            || h.ends_with(".snowflakecomputing.com.cn")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_query_param_replaces_existing() {
        let mut url =
            Url::parse("https://x.snowflakecomputing.com/q?request_guid=old&a=1").unwrap();
        set_query_param(&mut url, REQUEST_GUID_KEY, "new");
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("request_guid".to_string(), "new".to_string()),
            ]
        );
    }

    #[test]
    fn set_query_param_adds_when_absent() {
        let mut url = Url::parse("https://x.snowflakecomputing.com/q?a=1").unwrap();
        set_query_param(&mut url, REQUEST_GUID_KEY, "new");
        let v: Vec<_> = url.query_pairs().collect();
        assert_eq!(v.len(), 2);
        assert!(v.iter().any(|(k, val)| k == "request_guid" && val == "new"));
    }

    #[test]
    fn ensure_query_param_is_set_once() {
        let mut url = Url::parse("https://x.snowflakecomputing.com/q?clientStartTime=42").unwrap();
        ensure_query_param(&mut url, CLIENT_START_TIME_KEY, "99");
        let v: Vec<_> = url.query_pairs().collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "42");
    }

    #[test]
    fn ensure_query_param_adds_when_absent() {
        let mut url = Url::parse("https://x.snowflakecomputing.com/q").unwrap();
        ensure_query_param(&mut url, CLIENT_START_TIME_KEY, "99");
        let v: Vec<_> = url.query_pairs().collect();
        assert_eq!(v, vec![("clientStartTime".into(), "99".into())]);
    }

    #[test]
    fn snowflake_host_recognition() {
        assert!(is_snowflake_host(
            &Url::parse("https://acct.snowflakecomputing.com/x").unwrap()
        ));
        assert!(is_snowflake_host(
            &Url::parse("https://acct.privatelink.snowflakecomputing.com/x").unwrap()
        ));
        assert!(is_snowflake_host(
            &Url::parse("https://acct.snowflakecomputing.cn/x").unwrap()
        ));
        assert!(!is_snowflake_host(
            &Url::parse("https://s3.amazonaws.com/bucket/key").unwrap()
        ));
        assert!(!is_snowflake_host(
            &Url::parse("https://snowflakecomputing.com/x").unwrap()
        ));
    }

    use std::collections::HashMap;
    use std::collections::HashSet;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fast_policy() -> ExponentialBackoff {
        ExponentialBackoff::builder()
            .retry_bounds(Duration::from_millis(1), Duration::from_millis(5))
            .build_with_max_retries(5)
    }

    fn pairs(req: &wiremock::Request) -> HashMap<String, String> {
        req.url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// build a reqwest client whose dns resolution for the given snowflake-style
    /// host is rerouted to the wiremock listener, so urls of the form
    /// `http://acct.snowflakecomputing.com:PORT/...` actually hit the mock.
    fn rerouted_client(
        host: &str,
        addr: std::net::SocketAddr,
    ) -> reqwest_middleware::ClientWithMiddleware {
        let client = reqwest::Client::builder()
            .resolve(host, addr)
            .build()
            .unwrap();
        reqwest_middleware::ClientBuilder::new(client)
            .with(SnowflakeRetryMiddleware::new(fast_policy()))
            .build()
    }

    #[tokio::test]
    async fn rotates_request_guid_and_adds_retry_params_on_query_request() {
        let server = MockServer::start().await;

        // first two attempts get 503; third falls through to 200.
        Mock::given(method("GET"))
            .and(path("/queries/v1/query-request"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/queries/v1/query-request"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let addr = *server.address();
        let mw = rerouted_client("acct.snowflakecomputing.com", addr);
        let url = format!(
            "http://acct.snowflakecomputing.com:{}/queries/v1/query-request?requestId=req-abc",
            addr.port()
        );

        let resp = mw.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 3, "expected 3 attempts (2 retries)");

        let q0 = pairs(&received[0]);
        let q1 = pairs(&received[1]);
        let q2 = pairs(&received[2]);

        for q in [&q0, &q1, &q2] {
            assert_eq!(q.get("requestId").map(String::as_str), Some("req-abc"));
        }

        let guids: HashSet<String> = [&q0, &q1, &q2]
            .iter()
            .map(|q| {
                q.get("request_guid")
                    .cloned()
                    .expect("request_guid present")
            })
            .collect();
        assert_eq!(guids.len(), 3, "request_guid must rotate every attempt");

        // first attempt has no retry params or clientStartTime
        assert!(!q0.contains_key("retryCount"));
        assert!(!q0.contains_key("retryReason"));
        assert!(!q0.contains_key("clientStartTime"));

        // retry attempts carry full set; clientStartTime is set once and reused
        assert_eq!(q1.get("retryCount").map(String::as_str), Some("1"));
        assert_eq!(q1.get("retryReason").map(String::as_str), Some("503"));
        let cst = q1.get("clientStartTime").expect("clientStartTime present");
        assert_eq!(q2.get("retryCount").map(String::as_str), Some("2"));
        assert_eq!(q2.get("retryReason").map(String::as_str), Some("503"));
        assert_eq!(q2.get("clientStartTime"), Some(cst));
    }

    #[tokio::test]
    async fn rotates_request_guid_but_skips_retry_params_outside_query_request() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/session/v1/login-request"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/session/v1/login-request"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let addr = *server.address();
        let mw = rerouted_client("acct.snowflakecomputing.com", addr);
        let url = format!(
            "http://acct.snowflakecomputing.com:{}/session/v1/login-request?requestId=login-1",
            addr.port()
        );

        let resp = mw.post(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2);
        let q0 = pairs(&received[0]);
        let q1 = pairs(&received[1]);

        // request_guid still rotates per attempt
        assert_ne!(
            q0.get("request_guid").expect("guid"),
            q1.get("request_guid").expect("guid")
        );

        // but no retry params / clientStartTime on either attempt — those are query-request only
        for q in [&q0, &q1] {
            assert!(!q.contains_key("retryCount"));
            assert!(!q.contains_key("retryReason"));
            assert!(!q.contains_key("clientStartTime"));
        }
    }

    #[tokio::test]
    async fn does_not_inject_params_for_non_snowflake_host() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blob"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // hit wiremock directly — host is 127.0.0.1, not a snowflake domain.
        let client = reqwest::Client::new();
        let mw = reqwest_middleware::ClientBuilder::new(client)
            .with(SnowflakeRetryMiddleware::new(fast_policy()))
            .build();
        let url = format!("{}/blob?keep=me", server.uri());

        let resp = mw.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let q = pairs(&received[0]);
        assert_eq!(q.get("keep").map(String::as_str), Some("me"));
        assert!(!q.contains_key("request_guid"));
        assert!(!q.contains_key("retryCount"));
        assert!(!q.contains_key("clientStartTime"));
    }
}
