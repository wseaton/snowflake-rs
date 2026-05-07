//! External browser SSO authentication support.
//!
//! This module provides the helpers needed to authenticate via Snowflake's
//! external browser flow, where the user is redirected to their `IdP` in a browser
//! and the token is received via a local callback.

use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use thiserror::Error;
use url::Url;

const MAX_REQUEST_LINE_BYTES: usize = 16 * 1024;
/// <https://github.com/snowflakedb/gosnowflake/blob/v2.0.2/internal/config/dsn.go#L33-L34>
const LISTENER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Error, Debug)]
pub enum BrowserAuthError {
    #[error("Failed to bind local listener: {0}")]
    BindFailed(std::io::Error),

    #[error("Failed to get local address: {0}")]
    LocalAddrFailed(std::io::Error),

    #[error("Timed out waiting for browser callback after {}s", LISTENER_TIMEOUT.as_secs())]
    Timeout,

    #[error("Failed to accept connection: {0}")]
    AcceptFailed(std::io::Error),

    #[error("Failed to read request: {0}")]
    ReadFailed(std::io::Error),

    #[error("Invalid request format")]
    InvalidRequest,

    #[error("Expected GET request, got: {0}")]
    InvalidMethod(String),

    #[error("Request line exceeded {MAX_REQUEST_LINE_BYTES} bytes")]
    RequestTooLarge,

    #[error("Missing token in callback URL: {0}")]
    MissingToken(String),

    #[error("Received empty token in callback")]
    EmptyToken,

    #[error("Failed to URL decode token: {0}")]
    DecodeFailed(String),

    #[error("Failed to open browser: {0}")]
    BrowserOpenFailed(std::io::Error),
}

/// Generate a cryptographically secure proof key (32 bytes, base64 encoded).
///
/// This is used as part of the SSO challenge to verify the token came from
/// the expected authentication flow.
pub fn generate_proof_key() -> String {
    use base64::Engine;

    let mut randomness = [0u8; 32];
    getrandom::fill(&mut randomness).expect("failed to generate random bytes");
    base64::engine::general_purpose::STANDARD.encode(randomness)
}

/// Create a local TCP listener on localhost with a random available port.
///
/// Returns the listener and the port it's bound to.
pub fn create_local_listener() -> Result<(TcpListener, u16), BrowserAuthError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(BrowserAuthError::BindFailed)?;

    let port = listener
        .local_addr()
        .map_err(BrowserAuthError::LocalAddrFailed)?
        .port();

    Ok((listener, port))
}

/// Wait for the browser callback and extract the token.
///
/// The callback comes as: `GET /?token=<url_encoded_token> HTTP/1.1`
///
/// Blocks until a connection is received or `LISTENER_TIMEOUT` (120s) expires.
pub fn wait_for_token(listener: &TcpListener) -> Result<String, BrowserAuthError> {
    listener
        .set_nonblocking(true)
        .map_err(BrowserAuthError::ReadFailed)?;

    let deadline = Instant::now() + LISTENER_TIMEOUT;

    let (mut stream, _addr) = loop {
        match listener.accept() {
            Ok(conn) => break conn,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(BrowserAuthError::Timeout);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(BrowserAuthError::AcceptFailed(e)),
        }
    };

    let limited = (&stream).take(MAX_REQUEST_LINE_BYTES as u64);
    let mut reader = BufReader::new(limited);
    let mut request_line = String::new();

    let bytes_read = reader
        .read_line(&mut request_line)
        .map_err(BrowserAuthError::ReadFailed)?;

    if bytes_read >= MAX_REQUEST_LINE_BYTES {
        return Err(BrowserAuthError::RequestTooLarge);
    }

    let token = extract_token_from_request(&request_line)?;

    let response = "HTTP/1.1 200 OK\r\n\
Content-Type: text/html\r\n\
Connection: close\r\n\
\r\n\
<!doctype html>\
<html>\
<head>\
  <meta charset=\"utf-8\">\
  <title>Authentication Complete</title>\
  <style>\
    * { margin: 0; padding: 0; box-sizing: border-box; }\
    body {\
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;\
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\
      min-height: 100vh;\
      display: flex;\
      align-items: center;\
      justify-content: center;\
    }\
    .card {\
      background: white;\
      border-radius: 16px;\
      padding: 3em 4em;\
      text-align: center;\
      box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);\
    }\
    .checkmark { font-size: 4em; margin-bottom: 0.25em; color: #22c55e; }\
    h1 { color: #1a1a2e; font-weight: 600; margin-bottom: 0.5em; }\
    p { color: #6b7280; font-size: 1.1em; }\
  </style>\
  <script>\
    window.onload = function() { window.open('', '_self', ''); window.close(); };\
  </script>\
</head>\
<body>\
  <div class=\"card\">\
    <div class=\"checkmark\">&#10003;</div>\
    <h1>Authentication Successful</h1>\
    <p>You can close this tab.</p>\
  </div>\
  <script>setTimeout(function() { window.close(); }, 5000);</script>\
</body>\
</html>";

    let _ = stream.write_all(response.as_bytes());

    Ok(token)
}

/// Extract the token from the HTTP request line.
///
/// Expects: `GET /?token=<url_encoded_token> HTTP/1.1`
///
/// Uses `url::Url` for proper query-string parsing so extra params from the
/// `IdP` (e.g. `session_state`, `code`) don't leak into the token value.
fn extract_token_from_request(request_line: &str) -> Result<String, BrowserAuthError> {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(BrowserAuthError::InvalidRequest);
    }

    let method = parts[0];
    if method != "GET" {
        return Err(BrowserAuthError::InvalidMethod(method.to_string()));
    }

    let path = parts[1];

    // url::Url needs an absolute URL, so we prepend a dummy base
    let full = format!("http://localhost{path}");
    let parsed = Url::parse(&full).map_err(|_| BrowserAuthError::InvalidRequest)?;

    let token = parsed
        .query_pairs()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| BrowserAuthError::MissingToken(path.to_string()))?;

    if token.is_empty() {
        return Err(BrowserAuthError::EmptyToken);
    }

    Ok(token)
}

/// Open the SSO URL in the default browser.
pub fn open_browser(url: &str) -> Result<(), BrowserAuthError> {
    open::that(url).map_err(BrowserAuthError::BrowserOpenFailed)
}

#[cfg(test)]
mod tests {
    use crate::browser::BrowserAuthError;

    use super::extract_token_from_request;

    #[test]
    fn basic_token() {
        let req = "GET /?token=abc123 HTTP/1.1";
        assert_eq!(extract_token_from_request(req).unwrap(), "abc123");
    }

    #[test]
    fn url_encoded_token() {
        let req = "GET /?token=abc%20123 HTTP/1.1";
        assert_eq!(extract_token_from_request(req).unwrap(), "abc 123");
    }

    #[test]
    fn extra_query_params_ignored() {
        let req = "GET /?token=jwt.value.here&session_state=xyz&code=42 HTTP/1.1";
        assert_eq!(extract_token_from_request(req).unwrap(), "jwt.value.here");
    }

    #[test]
    fn token_with_equals_signs() {
        // base64-encoded JWTs often end with '=' padding
        let req = "GET /?token=eyJhbGciOi%3D%3D HTTP/1.1";
        assert_eq!(extract_token_from_request(req).unwrap(), "eyJhbGciOi==");
    }

    #[test]
    fn rejects_non_get_method() {
        let req = "POST /?token=abc123 HTTP/1.1";
        let err = extract_token_from_request(req).unwrap_err();
        assert!(matches!(err, BrowserAuthError::InvalidMethod(m) if m == "POST"));
    }

    #[test]
    fn rejects_missing_token_param() {
        let req = "GET /callback HTTP/1.1";
        assert!(matches!(
            extract_token_from_request(req).unwrap_err(),
            BrowserAuthError::MissingToken(_)
        ));
    }

    #[test]
    fn rejects_empty_token() {
        let req = "GET /?token= HTTP/1.1";
        assert!(matches!(
            extract_token_from_request(req).unwrap_err(),
            BrowserAuthError::EmptyToken
        ));
    }

    #[test]
    fn rejects_malformed_request() {
        let req = "GARBAGE";
        assert!(matches!(
            extract_token_from_request(req).unwrap_err(),
            BrowserAuthError::InvalidRequest
        ));
    }

    #[test]
    fn rejects_empty_request() {
        let req = "";
        assert!(matches!(
            extract_token_from_request(req).unwrap_err(),
            BrowserAuthError::InvalidRequest
        ));
    }

    #[test]
    fn proof_key_length() {
        let key = super::generate_proof_key();
        // base64 of 32 bytes is 44 characters
        assert_eq!(key.len(), 44);
    }
}
