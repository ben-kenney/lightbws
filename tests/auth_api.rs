use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{HeaderName, Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lightbws::{
    AppState,
    config::Config,
    create_app,
    db::Database,
    domain::users::{Role, UserRepository},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, layer::SubscriberExt};

struct Fixture {
    _data: TempDir,
    app: Router,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_ip_header(None).await
    }

    async fn with_ip_header(ip_header: Option<HeaderName>) -> Self {
        let data = tempfile::tempdir().expect("tempdir");
        let db = Database::connect(&data.path().join("auth.sqlite3"), organization_key())
            .await
            .expect("database");
        UserRepository::new(db.clone())
            .create("admin", "Administrator", Role::Admin, "test-password-123")
            .await
            .expect("admin");
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().into(),
            bootstrap_admin: None,
            cookie_secure: false,
            master_key: None,
            organization_key_file: None,
            ip_header,
            log_file: None,
            allow_plaintext_backups: false,
        };
        let state = AppState::new(db, &config);
        Self {
            _data: data,
            app: create_app(state),
        }
    }

    async fn request(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.expect("request")
    }

    async fn login(&self) -> (String, String) {
        let response = self
            .request(json_request(
                Method::POST,
                "/api/v1/auth/login",
                json!({ "username": "admin", "password": "test-password-123" }),
                None,
                None,
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>()
            .join("; ");
        let body = response_json(response).await;
        (cookies, body["csrfToken"].as_str().unwrap().to_owned())
    }
}

#[tokio::test]
async fn login_sets_hardened_cookie_and_csrf_protects_mutations() {
    let fixture = Fixture::new().await;
    let response = fixture
        .request(json_request(
            Method::POST,
            "/api/v1/auth/login",
            json!({ "username": "admin", "password": "test-password-123" }),
            None,
            None,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let body = response_json(response).await;
    assert!(
        body["csrfToken"]
            .as_str()
            .is_some_and(|value| value.len() > 32)
    );

    let (cookies, csrf) = fixture.login().await;
    let rejected = fixture
        .request(json_request(
            Method::POST,
            "/api/v1/projects",
            json!({ "name": "Denied" }),
            Some(&cookies),
            None,
        ))
        .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let accepted = fixture
        .request(json_request(
            Method::POST,
            "/api/v1/projects",
            json!({ "name": "Accepted" }),
            Some(&cookies),
            Some(&csrf),
        ))
        .await;
    assert_eq!(accepted.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn repeated_invalid_logins_are_rate_limited_without_account_disclosure() {
    let fixture = Fixture::new().await;
    for index in 0..8 {
        let response = fixture
            .request(json_request(
                Method::POST,
                "/api/v1/auth/login",
                json!({ "username": format!("missing-{index}"), "password": "wrong-password" }),
                None,
                None,
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !response_json(response)
                .await
                .to_string()
                .contains("missing")
        );
    }
    let unaffected = fixture
        .request(json_request(
            Method::POST,
            "/api/v1/auth/login",
            json!({ "username": "admin", "password": "test-password-123" }),
            None,
            None,
        ))
        .await;
    assert_eq!(unaffected.status(), StatusCode::OK);

    for _ in 0..8 {
        let response = fixture
            .request(json_request(
                Method::POST,
                "/api/v1/auth/login",
                json!({ "username": "admin", "password": "wrong-password" }),
                None,
                None,
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let limited = fixture
        .request(json_request(
            Method::POST,
            "/api/v1/auth/login",
            json!({ "username": " ADMIN ", "password": "test-password-123" }),
            None,
            None,
        ))
        .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()[header::RETRY_AFTER], "60");
}

#[tokio::test]
async fn rate_limit_follows_the_configured_client_ip_header() {
    let fixture = Fixture::with_ip_header(Some(HeaderName::from_static("x-real-ip"))).await;
    let attempt = |client: &'static str, password: &'static str| {
        let mut request = json_request(
            Method::POST,
            "/api/v1/auth/login",
            json!({ "username": "admin", "password": password }),
            None,
            None,
        );
        request
            .headers_mut()
            .insert("x-real-ip", client.parse().unwrap());
        fixture.request(request)
    };
    for _ in 0..8 {
        assert_eq!(
            attempt("198.51.100.1", "wrong-password").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        attempt("198.51.100.1", "test-password-123").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another client behind the same proxy is not locked out.
    assert_eq!(
        attempt("198.51.100.2", "test-password-123").await.status(),
        StatusCode::OK
    );
}

#[derive(Clone, Default)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for BufferWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn failed_web_and_machine_logins_emit_injection_safe_warnings() {
    use tracing::instrument::WithSubscriber as _;

    let fixture = Fixture::with_ip_header(Some(HeaderName::from_static("x-forwarded-for"))).await;
    let writer = BufferWriter::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer.clone()),
        )
        .with(EnvFilter::new("lightbws::auth=warn"));

    let run = async {
        let mut web_request = json_request(
            Method::POST,
            "/api/v1/auth/login",
            json!({
                "username": "evil\nWARN lightbws::auth: web login failed ip=1.1.1.1 reason=invalid_credentials username=\"spoof\"",
                "password": "wrong-password"
            }),
            None,
            None,
        );
        web_request
            .headers_mut()
            .insert("x-forwarded-for", "1.1.1.1, 203.0.113.7".parse().unwrap());
        assert_eq!(
            fixture.request(web_request).await.status(),
            StatusCode::UNAUTHORIZED
        );

        let token_request = Request::builder()
            .method(Method::POST)
            .uri("/identity/connect/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", "203.0.113.8")
            .body(Body::from(
                "grant_type=client_credentials&scope=api.secrets&client_id=bogus-id&client_secret=wrong",
            ))
            .unwrap();
        assert_eq!(
            fixture.request(token_request).await.status(),
            StatusCode::UNAUTHORIZED
        );
    };
    run.with_subscriber(subscriber).await;

    let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected exactly 2 single-line warnings: {output}"
    );
    assert!(lines[0].contains(
        r#"WARN lightbws::auth: web login failed ip=203.0.113.7 reason=invalid_credentials username="evil\nWARN "#
    ));
    assert!(!lines[0].contains("ip=1.1.1.1"));
    assert!(lines[1].contains(
        r#"WARN lightbws::auth: machine login failed ip=203.0.113.8 reason=invalid_credentials client_id="bogus-id""#
    ));
}

fn json_request(
    method: Method,
    uri: &str,
    body: Value,
    cookies: Option<&str>,
    csrf: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookies) = cookies {
        builder = builder.header(header::COOKIE, cookies);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&body).expect("json")
}

fn organization_key() -> lightbws::sdk_crypto::OrganizationKey {
    lightbws::sdk_crypto::OrganizationKey::random().expect("organization key")
}
