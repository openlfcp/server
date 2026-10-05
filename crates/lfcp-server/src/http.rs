//! The HTTP surface. LFCP-044 serves only the health endpoint; every other
//! path is 404 (the WebSocket endpoint arrives with LFCP-047, setup/admin
//! with LFCP-046).

use std::convert::Infallible;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};

/// The health check path.
pub const HEALTH_PATH: &str = "/health";

/// The health response body. It says the process is up and nothing else:
/// no keys, IDs, hosted Resources, credentials or application data.
pub const HEALTH_BODY: &str = "{\"status\":\"ok\"}";

/// Answer one HTTP request.
pub async fn handle(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(route(request.method(), request.uri().path()))
}

/// The response for a method and path.
pub fn route(method: &Method, path: &str) -> Response<Full<Bytes>> {
    let respond = |status, content_type, body: &'static str| {
        Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .expect("a static response is valid")
    };
    match (method, path) {
        (&Method::GET | &Method::HEAD, HEALTH_PATH) => {
            respond(StatusCode::OK, "application/json", HEALTH_BODY)
        }
        (_, HEALTH_PATH) => respond(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            "method not allowed\n",
        ),
        _ => respond(StatusCode::NOT_FOUND, "text/plain", "not found\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_and_other_paths() {
        assert_eq!(route(&Method::GET, "/health").status(), StatusCode::OK);
        assert_eq!(route(&Method::HEAD, "/health").status(), StatusCode::OK);
        assert_eq!(
            route(&Method::POST, "/health").status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(route(&Method::GET, "/").status(), StatusCode::NOT_FOUND);
        assert_eq!(route(&Method::GET, "/lfcp").status(), StatusCode::NOT_FOUND);
    }
}
