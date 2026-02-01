//! External browser SSO authentication support.
//!
//! This module provides the helpers needed to authenticate via Snowflake's
//! external browser flow, where the user is redirected to their `IdP` in a browser
//! and the token is received via a local callback.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrowserAuthError {
    #[error("Failed to bind local listener: {0}")]
    BindFailed(std::io::Error),

    #[error("Failed to get local address: {0}")]
    LocalAddrFailed(std::io::Error),

    #[error("Failed to accept connection: {0}")]
    AcceptFailed(std::io::Error),

    #[error("Failed to read request: {0}")]
    ReadFailed(std::io::Error),

    #[error("Invalid request format")]
    InvalidRequest,

    #[error("Missing token in callback URL: {0}")]
    MissingToken(String),

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
/// This function blocks until a connection is received and the token is extracted.
pub fn wait_for_token(listener: &TcpListener) -> Result<String, BrowserAuthError> {
    let (mut stream, _addr) = listener.accept().map_err(BrowserAuthError::AcceptFailed)?;

    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(BrowserAuthError::ReadFailed)?;

    let token = extract_token_from_request(&request_line)?;

    // Send a response that auto-closes after 1 second
    let response = "HTTP/1.1 200 OK\r\n\
        Content-Type: text/html\r\n\
        Connection: close\r\n\
        \r\n\
        <html><head><title>Authentication Complete</title></head><body>\
        <h2>Authentication successful!</h2>\
        <p>This window will close automatically...</p>\
        <script>setTimeout(function() { window.close(); }, 1000);</script>\
        </body></html>";

    let _ = stream.write_all(response.as_bytes());

    Ok(token)
}

/// Extract the token from the HTTP request line.
fn extract_token_from_request(request_line: &str) -> Result<String, BrowserAuthError> {
    // request_line looks like: GET /?token=<token> HTTP/1.1
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(BrowserAuthError::InvalidRequest);
    }

    let path = parts[1]; // /?token=<token>

    if !path.starts_with("/?token=") {
        return Err(BrowserAuthError::MissingToken(path.to_string()));
    }

    let encoded_token = &path[8..]; // skip "/?token="

    let token = urlencoding::decode(encoded_token)
        .map_err(|e| BrowserAuthError::DecodeFailed(e.to_string()))?
        .into_owned();

    Ok(token)
}

/// Open the SSO URL in the default browser.
pub fn open_browser(url: &str) -> Result<(), BrowserAuthError> {
    open::that(url).map_err(BrowserAuthError::BrowserOpenFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_token() {
        let request = "GET /?token=abc123 HTTP/1.1";
        let token = extract_token_from_request(request).unwrap();
        assert_eq!(token, "abc123");
    }

    #[test]
    fn test_extract_token_url_encoded() {
        let request = "GET /?token=abc%20123 HTTP/1.1";
        let token = extract_token_from_request(request).unwrap();
        assert_eq!(token, "abc 123");
    }

    #[test]
    fn test_generate_proof_key() {
        let key = generate_proof_key();
        // base64 of 32 bytes is 44 characters
        assert_eq!(key.len(), 44);
    }

    #[test]
    fn test_missing_token_error() {
        let request = "GET /callback HTTP/1.1";
        let result = extract_token_from_request(request);
        assert!(matches!(result, Err(BrowserAuthError::MissingToken(_))));
    }
}
