//! Checks the warnings written for refused logins.
//!
//! This test lives in its own test binary on purpose. It captures log output with a scoped
//! subscriber, and tracing caches per-callsite interest globally. When other tests in the same
//! binary hit the same login callsites at the same time without a subscriber, that cache can
//! briefly say "never" and an event is dropped, which made this test flaky.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{HeaderName, Method, Request, StatusCode, header},
};
use lightbws::{
    AppState,
    config::Config,
    create_app,
    db::Database,
    domain::users::{Role, UserRepository},
};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, layer::SubscriberExt};

struct Fixture {
    _data: TempDir,
    app: Router,
}

impl Fixture {
    async fn with_ip_header(ip_header: HeaderName) -> Self {
        let data = tempfile::tempdir().expect("tempdir");
        let organization_key =
            lightbws::sdk_crypto::OrganizationKey::random().expect("organization key");
        let db = Database::connect(&data.path().join("auth.sqlite3"), organization_key)
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
            ip_header: Some(ip_header),
            log_file: None,
            secret_history_limit: 20,
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
    let fixture = Fixture::with_ip_header(HeaderName::from_static("x-forwarded-for")).await;
    let writer = BufferWriter::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer.clone()),
        )
        .with(EnvFilter::new("lightbws::auth=warn"));

    let run = async {
        let web_request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "1.1.1.1, 203.0.113.7")
            .body(Body::from(
                json!({
                    "username": "evil\nWARN lightbws::auth: web login failed ip=1.1.1.1 reason=invalid_credentials username=\"spoof\"",
                    "password": "wrong-password"
                })
                .to_string(),
            ))
            .unwrap();
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
    // The spoofed text stays inside the escaped username value. Only the fields before it must
    // be free of the forged address, since the username itself is logged as sent.
    let (fields, _username) = lines[0].split_once(" username=").expect("username field");
    assert!(!fields.contains("1.1.1.1"), "forged ip in fields: {fields}");
    assert!(lines[1].contains(
        r#"WARN lightbws::auth: machine login failed ip=203.0.113.8 reason=invalid_credentials client_id="bogus-id""#
    ));
}
