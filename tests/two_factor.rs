use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lightbws::{
    AppState,
    config::Config,
    create_app,
    crypto::MasterKey,
    db::Database,
    domain::{
        transfer::{BackupScopes, dump_database_scoped, import_database_scoped},
        two_factor::{TwoFactorPolicy, break_glass_reset},
        users::{Role, UserRepository},
    },
    sdk_crypto::OrganizationKey,
    totp,
};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, layer::SubscriberExt};

const PASSWORD: &str = "test-password-123";

struct Fixture {
    _data: TempDir,
    app: Router,
    db: Database,
    master_key: MasterKey,
}

struct Session {
    cookies: String,
    csrf: String,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_policy(TwoFactorPolicy::Off).await
    }

    async fn with_policy(require_2fa: TwoFactorPolicy) -> Self {
        let data = tempfile::tempdir().expect("tempdir");
        let db = Database::connect(&data.path().join("two-factor.sqlite3"), key())
            .await
            .expect("database");
        let users = UserRepository::new(db.clone());
        users
            .create("admin", "Administrator", Role::Admin, PASSWORD)
            .await
            .expect("admin");
        users
            .create("member", "Member", Role::User, PASSWORD)
            .await
            .expect("member");
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().into(),
            bootstrap_admin: None,
            cookie_secure: false,
            master_key: None,
            organization_key_file: None,
            ip_header: None,
            log_file: None,
            secret_history_limit: 20,
            require_2fa,
            reset_2fa_for: None,
            allow_plaintext_backups: false,
        };
        let master_key = MasterKey::random().expect("master key");
        Self {
            _data: data,
            app: create_app(AppState::new(db.clone(), &config).with_master_key(master_key.clone())),
            db,
            master_key,
        }
    }

    async fn request(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.expect("request")
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        session: Option<&Session>,
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(path);
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(session) = session {
            builder = builder
                .header(header::COOKIE, &session.cookies)
                .header("x-csrf-token", &session.csrf);
        }
        self.request(
            builder
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap(),
        )
        .await
    }

    async fn password_step(&self, username: &str) -> axum::response::Response {
        self.call(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({ "username": username, "password": PASSWORD })),
            None,
        )
        .await
    }

    /// Signs in a user that has no second factor.
    async fn login(&self, username: &str) -> Session {
        let response = self.password_step(username).await;
        assert_eq!(response.status(), StatusCode::OK);
        session_of(response).await.0
    }

    /// Password step for an enrolled user: returns the challenge token.
    async fn challenge(&self, username: &str) -> String {
        let response = self.password_step(username).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = response_json(response).await;
        assert_eq!(body["twoFactorRequired"], true);
        assert_eq!(body["methods"], json!(["totp"]));
        assert!(body.get("user").is_none() && body.get("csrfToken").is_none());
        body["challenge"].as_str().unwrap().to_owned()
    }

    async fn second_step(&self, body: Value) -> axum::response::Response {
        self.call(Method::POST, "/api/v1/auth/login/2fa", Some(body), None)
            .await
    }

    /// Enrols the signed-in user and returns the secret and the recovery codes.
    async fn enroll(&self, session: &Session) -> (Vec<u8>, Vec<String>) {
        let setup = self
            .call(
                Method::POST,
                "/api/v1/auth/2fa/totp/setup",
                Some(json!({ "password": PASSWORD })),
                Some(session),
            )
            .await;
        assert_eq!(setup.status(), StatusCode::OK);
        let setup = response_json(setup).await;
        let secret = totp::base32_decode(setup["secret"].as_str().unwrap()).unwrap();
        assert_eq!(secret.len(), 20);
        assert!(
            setup["uri"]
                .as_str()
                .unwrap()
                .starts_with("otpauth://totp/LightBWS:")
        );
        // The first code comes from the previous step so later sign-ins still have fresh steps.
        let confirm = self
            .call(
                Method::POST,
                "/api/v1/auth/2fa/totp/confirm",
                Some(json!({ "code": code(&secret, -1) })),
                Some(session),
            )
            .await;
        assert_eq!(confirm.status(), StatusCode::OK);
        let codes = response_json(confirm).await["recoveryCodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(codes.len(), 10);
        (secret, codes)
    }

    /// Lets the next code be accepted regardless of the steps earlier requests consumed.
    async fn forget_used_steps(&self) {
        self.db
            .connection()
            .execute_unprepared("UPDATE user_totp SET last_used_step = NULL")
            .await
            .expect("reset used step");
    }

    async fn scalar(&self, sql: &str) -> i64 {
        scalar(&self.db, sql).await
    }
}

#[tokio::test]
async fn users_without_a_second_factor_sign_in_as_before() {
    let fixture = Fixture::new().await;
    let response = fixture.password_step("admin").await;
    assert_eq!(response.status(), StatusCode::OK);
    let (session, body) = session_of(response).await;
    assert!(session.cookies.contains("lightbws_session="));
    assert_eq!(body["user"]["username"], "admin");
    assert_eq!(body["user"]["twoFactorEnabled"], false);
    assert!(body.get("twoFactorRequired").is_none());
    assert!(body.get("twoFactorEnrollmentRequired").is_none());

    let status = fixture
        .call(Method::GET, "/api/v1/auth/2fa/status", None, Some(&session))
        .await;
    assert_eq!(
        response_json(status).await,
        json!({ "enabled": false, "totpEnabled": false, "recoveryCodesRemaining": 0, "required": false })
    );
}

#[tokio::test]
async fn enrollment_needs_the_password_and_a_valid_code_and_revokes_other_sessions() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let other_session = fixture.login("admin").await;

    let wrong_password = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/setup",
            Some(json!({ "password": "not-the-password" })),
            Some(&session),
        )
        .await;
    assert_eq!(wrong_password.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(wrong_password).await["error"]["code"],
        "INVALID_CREDENTIALS"
    );
    let without_csrf = fixture
        .request(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/2fa/totp/setup")
                .header(header::COOKIE, &session.cookies)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "password": PASSWORD }).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(without_csrf.status(), StatusCode::FORBIDDEN);

    let setup = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/setup",
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    let secret_text = response_json(setup).await["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    // A pending secret does not change sign-in yet.
    assert_eq!(
        fixture.password_step("admin").await.status(),
        StatusCode::OK
    );
    let wrong_code = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/confirm",
            Some(json!({ "code": "000000" })),
            Some(&session),
        )
        .await;
    assert_eq!(wrong_code.status(), StatusCode::FORBIDDEN);

    let (secret, recovery_codes) = fixture.enroll(&session).await;
    // Starting again replaced the pending secret that was never confirmed.
    assert_ne!(totp::base32_encode(&secret), secret_text);

    // The enrolling session survives; every other session of the user is gone.
    let current = fixture
        .call(Method::GET, "/api/v1/auth/session", None, Some(&session))
        .await;
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(
        response_json(current).await["user"]["twoFactorEnabled"],
        true
    );
    let revoked = fixture
        .call(
            Method::GET,
            "/api/v1/auth/session",
            None,
            Some(&other_session),
        )
        .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.2fa.enable'")
            .await,
        1
    );

    // Neither the secret nor the codes are stored in a readable form.
    let stored_secret = fixture
        .db
        .connection()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT secret_cipher AS value FROM user_totp",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<String>("", "value")
        .unwrap();
    assert!(!stored_secret.contains(&totp::base32_encode(&secret)));
    assert!(
        fixture
            .master_key
            .decrypt(b"another user", &stored_secret)
            .is_err()
    );
    let digests = fixture
        .db
        .connection()
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT code_digest AS value FROM user_recovery_codes",
        ))
        .await
        .unwrap();
    assert_eq!(digests.len(), 10);
    for row in digests {
        let digest = row.try_get::<String>("", "value").unwrap();
        assert_eq!(digest.len(), 64);
        assert!(recovery_codes.iter().all(|code| !digest.contains(code)));
    }

    // Enrolling again is refused while a confirmed secret exists.
    let again = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/setup",
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    // The secret appears in no later response.
    let status = fixture
        .call(Method::GET, "/api/v1/auth/2fa/status", None, Some(&session))
        .await;
    let status = response_json(status).await;
    assert_eq!(status["enabled"], true);
    assert_eq!(status["recoveryCodesRemaining"], 10);
    assert!(!status.to_string().contains(&totp::base32_encode(&secret)));
}

#[tokio::test]
async fn sign_in_with_a_second_factor_needs_a_fresh_valid_code() {
    use tracing::instrument::WithSubscriber as _;

    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let (secret, _) = fixture.enroll(&session).await;

    // A wrong password looks the same whether or not the account has a second factor.
    let wrong_password = |username: &'static str| {
        fixture.call(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({ "username": username, "password": "wrong-password" })),
            None,
        )
    };
    let enrolled = wrong_password("admin").await;
    let plain = wrong_password("member").await;
    assert_eq!(enrolled.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(plain.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response_json(enrolled).await, response_json(plain).await);

    let challenge = fixture.challenge("admin").await;
    let writer = BufferWriter::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer.clone()),
        )
        .with(EnvFilter::new("lightbws::auth=warn"));
    let wrong = fixture
        .second_step(json!({ "challenge": challenge, "code": "000000" }))
        .with_subscriber(subscriber)
        .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(wrong.headers().get(header::SET_COOKIE).is_none());
    let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    assert_eq!(output.lines().count(), 1, "{output}");
    assert!(output.contains(
        r#"WARN lightbws::auth: web login failed ip=unknown reason=invalid_second_factor username="admin""#
    ));

    let both = fixture
        .second_step(json!({ "challenge": challenge, "code": "000000", "recoveryCode": "x" }))
        .await;
    assert_eq!(both.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let valid_code = code(&secret, 0);
    let signed_in = fixture
        .second_step(json!({ "challenge": challenge, "code": valid_code }))
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let (new_session, body) = session_of(signed_in).await;
    assert_eq!(body["user"]["username"], "admin");
    let current = fixture
        .call(
            Method::GET,
            "/api/v1/auth/session",
            None,
            Some(&new_session),
        )
        .await;
    assert_eq!(current.status(), StatusCode::OK);

    // The challenge worked once.
    let reused = fixture
        .second_step(json!({ "challenge": challenge, "code": code(&secret, 1) }))
        .await;
    assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);
    // The code worked once, even on a new challenge.
    let challenge = fixture.challenge("admin").await;
    let replayed = fixture
        .second_step(json!({ "challenge": challenge, "code": valid_code }))
        .await;
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);

    // An expired challenge is rejected even with a valid code.
    fixture.forget_used_steps().await;
    let challenge = fixture.challenge("admin").await;
    fixture
        .db
        .connection()
        .execute_unprepared("UPDATE login_challenges SET created_at = 0, expires_at = 1")
        .await
        .unwrap();
    let expired = fixture
        .second_step(json!({ "challenge": challenge, "code": code(&secret, 0) }))
        .await;
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);

    // Five wrong codes use the challenge up; the right code no longer helps.
    let challenge = fixture.challenge("admin").await;
    // Starting a sign-in also swept every expired challenge.
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM login_challenges")
            .await,
        1
    );
    for _ in 0..5 {
        let wrong = fixture
            .second_step(json!({ "challenge": challenge, "code": "000000" }))
            .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }
    let exhausted = fixture
        .second_step(json!({ "challenge": challenge, "code": code(&secret, 0) }))
        .await;
    assert_eq!(exhausted.status(), StatusCode::UNAUTHORIZED);

    // A disabled user cannot finish a challenge issued earlier.
    let challenge = fixture.challenge("admin").await;
    fixture
        .db
        .connection()
        .execute_unprepared("UPDATE users SET disabled = 1 WHERE username = 'admin'")
        .await
        .unwrap();
    let disabled = fixture
        .second_step(json!({ "challenge": challenge, "code": code(&secret, 0) }))
        .await;
    assert_eq!(disabled.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_codes_from_one_address_are_rate_limited() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    fixture.enroll(&session).await;
    let mut limited = false;
    for _ in 0..8 {
        let challenge = fixture.challenge("admin").await;
        for _ in 0..5 {
            let response = fixture
                .second_step(json!({ "challenge": challenge, "code": "000000" }))
                .await;
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                limited = true;
            }
        }
    }
    assert!(
        limited,
        "30 wrong codes a minute must hit the address limit"
    );
}

#[tokio::test]
async fn recovery_codes_work_once_and_regenerating_replaces_them() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let (secret, codes) = fixture.enroll(&session).await;

    let challenge = fixture.challenge("admin").await;
    let signed_in = fixture
        .second_step(json!({ "challenge": challenge, "recoveryCode": codes[0].to_lowercase() }))
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let (session, _) = session_of(signed_in).await;
    assert_eq!(
        fixture
            .scalar(
                "SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.2fa.recovery_code.used'"
            )
            .await,
        1
    );
    let challenge = fixture.challenge("admin").await;
    let reused = fixture
        .second_step(json!({ "challenge": challenge, "recoveryCode": codes[0] }))
        .await;
    assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);

    let status = fixture
        .call(Method::GET, "/api/v1/auth/2fa/status", None, Some(&session))
        .await;
    assert_eq!(response_json(status).await["recoveryCodesRemaining"], 9);

    let regenerate = |body: Value| {
        fixture.call(
            Method::POST,
            "/api/v1/auth/2fa/recovery-codes/regenerate",
            Some(body),
            Some(&session),
        )
    };
    let wrong_code = regenerate(json!({ "password": PASSWORD, "code": "000000" })).await;
    assert_eq!(wrong_code.status(), StatusCode::FORBIDDEN);
    let regenerated = regenerate(json!({ "password": PASSWORD, "code": code(&secret, 0) })).await;
    assert_eq!(regenerated.status(), StatusCode::OK);
    let new_codes = response_json(regenerated).await["recoveryCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(new_codes.len(), 10);
    assert!(new_codes.iter().all(|code| !codes.contains(code)));

    let challenge = fixture.challenge("admin").await;
    let old = fixture
        .second_step(json!({ "challenge": challenge, "recoveryCode": codes[1] }))
        .await;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let new = fixture
        .second_step(json!({ "challenge": challenge, "recoveryCode": new_codes[0] }))
        .await;
    assert_eq!(new.status(), StatusCode::OK);
}

#[tokio::test]
async fn disabling_and_password_change_need_the_second_factor() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let (secret, codes) = fixture.enroll(&session).await;

    let change = |body: Value| {
        fixture.call(
            Method::POST,
            "/api/v1/auth/password",
            Some(body),
            Some(&session),
        )
    };
    let missing_code = change(json!({
        "currentPassword": PASSWORD, "newPassword": "a-new-long-password"
    }))
    .await;
    assert_eq!(missing_code.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let wrong_password = change(json!({
        "currentPassword": "wrong", "newPassword": "a-new-long-password", "code": code(&secret, 0)
    }))
    .await;
    assert_eq!(wrong_password.status(), StatusCode::FORBIDDEN);
    let changed = change(json!({
        "currentPassword": PASSWORD, "newPassword": "a-new-long-password", "code": code(&secret, 0)
    }))
    .await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    let old_password = fixture.password_step("admin").await;
    assert_eq!(old_password.status(), StatusCode::UNAUTHORIZED);

    let disable = |body: Value| {
        fixture.call(
            Method::DELETE,
            "/api/v1/auth/2fa/totp",
            Some(body),
            Some(&session),
        )
    };
    let without_factor = disable(json!({ "password": "a-new-long-password" })).await;
    assert_eq!(without_factor.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let disabled = disable(json!({
        "password": "a-new-long-password", "recoveryCode": codes[0]
    }))
    .await;
    assert_eq!(disabled.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_totp")
            .await
            + fixture
                .scalar("SELECT COUNT(*) AS value FROM user_recovery_codes")
                .await,
        0
    );
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.2fa.disable'")
            .await,
        1
    );
    // Sign-in is a single step again.
    let response = fixture
        .call(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({ "username": "admin", "password": "a-new-long-password" })),
            None,
        )
        .await;
    assert!(response.headers().get(header::SET_COOKIE).is_some());
}

#[tokio::test]
async fn administrators_can_reset_another_users_second_factor() {
    let fixture = Fixture::new().await;
    let member = fixture.login("member").await;
    fixture.enroll(&member).await;
    let admin = fixture.login("admin").await;
    fixture.enroll(&admin).await;

    let users = fixture
        .call(Method::GET, "/api/v1/admin/users", None, Some(&admin))
        .await;
    let users = response_json(users).await;
    let users = users.as_array().unwrap();
    assert!(users.iter().all(|user| user["twoFactorEnabled"] == true));
    let id_of = |name: &str| {
        users.iter().find(|user| user["username"] == name).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let by_member = fixture
        .call(
            Method::DELETE,
            &format!("/api/v1/admin/users/{}/2fa", id_of("admin")),
            None,
            Some(&member),
        )
        .await;
    assert_eq!(by_member.status(), StatusCode::FORBIDDEN);
    let own = fixture
        .call(
            Method::DELETE,
            &format!("/api/v1/admin/users/{}/2fa", id_of("admin")),
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(own.status(), StatusCode::CONFLICT);

    let reset = fixture
        .call(
            Method::DELETE,
            &format!("/api/v1/admin/users/{}/2fa", id_of("member")),
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.2fa.reset'")
            .await,
        1
    );
    // The member is signed out and signs in with the password alone again.
    let revoked = fixture
        .call(Method::GET, "/api/v1/auth/session", None, Some(&member))
        .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let response = fixture.password_step("member").await;
    assert!(response.headers().get(header::SET_COOKIE).is_some());
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_totp")
            .await,
        1
    );
}

#[tokio::test]
async fn required_enrollment_limits_a_session_to_the_enrollment_routes() {
    let fixture = Fixture::with_policy(TwoFactorPolicy::Admins).await;
    // Members are not covered by the `admins` policy.
    let member = fixture.login("member").await;
    let overview = fixture
        .call(Method::GET, "/api/v1/overview", None, Some(&member))
        .await;
    assert_eq!(overview.status(), StatusCode::OK);

    let response = fixture.password_step("admin").await;
    let (admin, body) = session_of(response).await;
    assert_eq!(body["twoFactorEnrollmentRequired"], true);
    for (method, path) in [
        (Method::GET, "/api/v1/overview"),
        (Method::GET, "/api/v1/secrets"),
        (Method::GET, "/api/v1/admin/users"),
        (Method::POST, "/api/v1/projects"),
    ] {
        let blocked = fixture
            .call(method, path, Some(json!({ "name": "x" })), Some(&admin))
            .await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            response_json(blocked).await["error"]["code"],
            "TWO_FACTOR_ENROLLMENT_REQUIRED"
        );
    }
    let current = fixture
        .call(Method::GET, "/api/v1/auth/session", None, Some(&admin))
        .await;
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(
        response_json(current).await["twoFactorEnrollmentRequired"],
        true
    );
    let status = fixture
        .call(Method::GET, "/api/v1/auth/2fa/status", None, Some(&admin))
        .await;
    assert_eq!(response_json(status).await["required"], true);

    let (secret, codes) = fixture.enroll(&admin).await;
    let overview = fixture
        .call(Method::GET, "/api/v1/overview", None, Some(&admin))
        .await;
    assert_eq!(overview.status(), StatusCode::OK);

    // A required second factor cannot be switched off again.
    let disable = fixture
        .call(
            Method::DELETE,
            "/api/v1/auth/2fa/totp",
            Some(json!({ "password": PASSWORD, "code": code(&secret, 0) })),
            Some(&admin),
        )
        .await;
    assert_eq!(disable.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let _ = codes;

    let logout = fixture
        .call(Method::POST, "/api/v1/auth/logout", None, Some(&admin))
        .await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn break_glass_removes_the_named_users_second_factor_once() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    fixture.enroll(&session).await;

    assert!(
        !break_glass_reset(&fixture.db, &fixture.master_key, "nobody")
            .await
            .unwrap()
    );
    assert!(
        break_glass_reset(&fixture.db, &fixture.master_key, "admin")
            .await
            .unwrap()
    );
    assert_eq!(
        fixture
            .scalar(
                "SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.2fa.reset' AND actor_kind = 'system'"
            )
            .await,
        1
    );
    let revoked = fixture
        .call(Method::GET, "/api/v1/auth/session", None, Some(&session))
        .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let response = fixture.password_step("admin").await;
    assert!(response.headers().get(header::SET_COOKIE).is_some());
    // Leaving the setting in place does nothing more.
    assert!(
        !break_glass_reset(&fixture.db, &fixture.master_key, "admin")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn archives_keep_the_same_authenticator_across_master_keys() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let (secret, codes) = fixture.enroll(&session).await;
    // A pending enrolment is not exported.
    let member = fixture.login("member").await;
    let pending = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/setup",
            Some(json!({ "password": PASSWORD })),
            Some(&member),
        )
        .await;
    assert_eq!(pending.status(), StatusCode::OK);

    let dump = dump_database_scoped(
        &fixture.db,
        &fixture.master_key,
        BackupScopes::full_instance(),
    )
    .await
    .expect("dump");
    let archived: Value = serde_json::from_slice(&dump).unwrap();
    assert_eq!(archived["userTotp"].as_array().unwrap().len(), 1);
    assert_eq!(archived["userRecoveryCodes"].as_array().unwrap().len(), 10);
    // Without the identities scope the archive carries no second factors.
    let secrets_only =
        dump_database_scoped(&fixture.db, &fixture.master_key, BackupScopes::default())
            .await
            .expect("dump");
    let secrets_only: Value = serde_json::from_slice(&secrets_only).unwrap();
    assert!(secrets_only.get("userTotp").is_none());
    assert!(secrets_only.get("userRecoveryCodes").is_none());

    let target_data = tempfile::tempdir().expect("tempdir");
    let target = Database::connect(&target_data.path().join("target.sqlite3"), key())
        .await
        .expect("target");
    let target_master_key = MasterKey::random().expect("master key");
    import_database_scoped(&target, &target_master_key, &dump, true, false)
        .await
        .expect("restore");
    assert_eq!(
        scalar(&target, "SELECT COUNT(*) AS value FROM user_totp").await,
        1
    );
    let restored = Fixture::over(target.clone(), target_master_key, target_data);
    let challenge = restored.challenge("admin").await;
    let signed_in = restored
        .second_step(json!({ "challenge": challenge, "code": code(&secret, 1) }))
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let challenge = restored.challenge("admin").await;
    let recovered = restored
        .second_step(json!({ "challenge": challenge, "recoveryCode": codes[3] }))
        .await;
    assert_eq!(recovered.status(), StatusCode::OK);

    // An archive written before two-factor sign-in existed still imports.
    let mut without_sections = archived.clone();
    let object = without_sections.as_object_mut().unwrap();
    object.remove("userTotp");
    object.remove("userRecoveryCodes");
    let legacy_data = tempfile::tempdir().expect("tempdir");
    let legacy = Database::connect(&legacy_data.path().join("legacy.sqlite3"), key())
        .await
        .expect("legacy target");
    import_database_scoped(
        &legacy,
        &MasterKey::random().unwrap(),
        &serde_json::to_vec(&without_sections).unwrap(),
        true,
        false,
    )
    .await
    .expect("archive without second factors");
    assert_eq!(
        scalar(&legacy, "SELECT COUNT(*) AS value FROM user_totp").await,
        0
    );

    // A second factor for a user the archive does not contain is rejected.
    let mut forged = archived;
    forged["userTotp"][0]["userId"] = json!(uuid::Uuid::new_v4().to_string());
    assert!(
        import_database_scoped(
            &legacy,
            &MasterKey::random().unwrap(),
            &serde_json::to_vec(&forged).unwrap(),
            false,
            false,
        )
        .await
        .is_err()
    );
}

impl Fixture {
    /// Serves an already populated database, as a restored instance would.
    fn over(db: Database, master_key: MasterKey, data: TempDir) -> Self {
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().into(),
            bootstrap_admin: None,
            cookie_secure: false,
            master_key: None,
            organization_key_file: None,
            ip_header: None,
            log_file: None,
            secret_history_limit: 20,
            require_2fa: TwoFactorPolicy::Off,
            reset_2fa_for: None,
            allow_plaintext_backups: false,
        };
        Self {
            app: create_app(AppState::new(db.clone(), &config).with_master_key(master_key.clone())),
            _data: data,
            db,
            master_key,
        }
    }
}

/// The code an authenticator shows now, or `offset` time steps away.
fn code(secret: &[u8], offset: i64) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    totp::code_at(secret, totp::step_at(now) + offset)
}

async fn session_of(response: axum::response::Response) -> (Session, Value) {
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let body = response_json(response).await;
    let csrf = body["csrfToken"].as_str().unwrap_or_default().to_owned();
    (Session { cookies, csrf }, body)
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

async fn scalar(db: &Database, sql: &str) -> i64 {
    db.connection()
        .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
        .await
        .expect("query")
        .expect("row")
        .try_get::<i64>("", "value")
        .expect("value")
}

fn key() -> OrganizationKey {
    OrganizationKey::random().expect("organization key")
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
