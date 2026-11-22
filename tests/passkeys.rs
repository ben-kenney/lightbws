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
    crypto::MasterKey,
    db::Database,
    domain::{
        transfer::{BackupScopes, dump_database_scoped, import_database_scoped},
        two_factor::{TwoFactorPolicy, break_glass_reset},
        users::{Role, UserRepository},
    },
    sdk_crypto::OrganizationKey,
    totp,
    webauthn::{
        RelyingParty,
        testing::{AssertionResponse, SoftwareAuthenticator, encode},
    },
};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, layer::SubscriberExt};

const PASSWORD: &str = "test-password-123";
const PUBLIC_URL: &str = "https://secrets.example.com";
const ORIGIN: &str = "https://secrets.example.com";
const RP_ID: &str = "secrets.example.com";

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

struct Options {
    public_url: Option<&'static str>,
    require_2fa: TwoFactorPolicy,
    ip_header: Option<HeaderName>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            public_url: Some(PUBLIC_URL),
            require_2fa: TwoFactorPolicy::Off,
            ip_header: None,
        }
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with(Options::default()).await
    }

    async fn with(options: Options) -> Self {
        let data = tempfile::tempdir().expect("tempdir");
        let db = Database::connect(&data.path().join("passkeys.sqlite3"), key())
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
        Self::over(db, MasterKey::random().expect("master key"), data, options)
    }

    /// Serves an existing database, as a restored instance would.
    fn over(db: Database, master_key: MasterKey, data: TempDir, options: Options) -> Self {
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().into(),
            bootstrap_admin: None,
            cookie_secure: false,
            master_key: None,
            organization_key_file: None,
            ip_header: options.ip_header,
            log_file: None,
            secret_history_limit: 20,
            require_2fa: options.require_2fa,
            reset_2fa_for: None,
            public_url: options
                .public_url
                .map(|url| RelyingParty::from_public_url(url).unwrap()),
            allow_plaintext_backups: false,
        };
        Self {
            app: create_app(AppState::new(db.clone(), &config).with_master_key(master_key.clone())),
            _data: data,
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

    /// Password step for a user with a second factor: the challenge token and the methods.
    async fn challenge(&self, username: &str) -> (String, Value) {
        let response = self.password_step(username).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = response_json(response).await;
        assert_eq!(body["twoFactorRequired"], true);
        (
            body["challenge"].as_str().unwrap().to_owned(),
            body["methods"].clone(),
        )
    }

    async fn register_options(&self, session: &Session) -> Value {
        let response = self
            .call(
                Method::POST,
                "/api/v1/auth/passkeys/register/options",
                Some(json!({ "password": PASSWORD })),
                Some(session),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await["publicKey"].clone()
    }

    async fn register_verify(
        &self,
        session: &Session,
        authenticator: &SoftwareAuthenticator,
        challenge: &str,
        name: &str,
    ) -> axum::response::Response {
        let created = authenticator.create(RP_ID, ORIGIN, challenge);
        self.call(
            Method::POST,
            "/api/v1/auth/passkeys/register/verify",
            Some(json!({
                "name": name,
                "credential": {
                    "id": encode(&authenticator.credential_id),
                    "rawId": encode(&authenticator.credential_id),
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": encode(&created.client_data_json),
                        "attestationObject": encode(&created.attestation_object),
                        "transports": ["internal", "hybrid", "made-up"],
                    },
                },
            })),
            Some(session),
        )
        .await
    }

    /// Adds a passkey to the signed-in account and returns the response body.
    async fn register(
        &self,
        session: &Session,
        authenticator: &SoftwareAuthenticator,
        name: &str,
    ) -> Value {
        let options = self.register_options(session).await;
        let response = self
            .register_verify(
                session,
                authenticator,
                options["challenge"].as_str().unwrap(),
                name,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        response_json(response).await
    }

    /// Starts a passkey-only sign-in and returns the challenge.
    async fn sign_in_challenge(&self) -> String {
        let response = self
            .call(Method::POST, "/api/v1/auth/passkey/options", None, None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let options = response_json(response).await["publicKey"].clone();
        assert_eq!(options["rpId"], RP_ID);
        assert_eq!(options["userVerification"], "required");
        assert_eq!(options["allowCredentials"], json!([]));
        options["challenge"].as_str().unwrap().to_owned()
    }

    async fn sign_in(&self, credential: Value) -> axum::response::Response {
        self.call(
            Method::POST,
            "/api/v1/auth/passkey/verify",
            Some(json!({ "credential": credential })),
            None,
        )
        .await
    }

    async fn second_step(&self, credential: Value) -> axum::response::Response {
        self.call(
            Method::POST,
            "/api/v1/auth/login/passkey/verify",
            Some(json!({ "credential": credential })),
            None,
        )
        .await
    }

    /// A complete passkey-only sign-in with a fresh challenge.
    async fn sign_in_with(&self, authenticator: &mut SoftwareAuthenticator) -> StatusCode {
        let challenge = self.sign_in_challenge().await;
        let response = authenticator.get(RP_ID, ORIGIN, &challenge);
        self.sign_in(credential(authenticator, &response, None))
            .await
            .status()
    }

    async fn user_id(&self, username: &str) -> uuid::Uuid {
        let row = self
            .db
            .connection()
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT id AS value FROM users WHERE username = ?",
                [username.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        row.try_get::<String>("", "value").unwrap().parse().unwrap()
    }

    async fn scalar(&self, sql: &str) -> i64 {
        scalar(&self.db, sql).await
    }
}

/// The JSON a browser sends for an assertion.
fn credential(
    authenticator: &SoftwareAuthenticator,
    response: &AssertionResponse,
    user_handle: Option<&[u8]>,
) -> Value {
    json!({
        "id": encode(&authenticator.credential_id),
        "rawId": encode(&authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": encode(&response.client_data_json),
            "authenticatorData": encode(&response.authenticator_data),
            "signature": encode(&response.signature),
            "userHandle": user_handle.map(encode),
        },
    })
}

#[tokio::test]
async fn passkeys_are_off_without_a_public_url() {
    let fixture = Fixture::with(Options {
        public_url: None,
        ..Options::default()
    })
    .await;
    let config = fixture
        .call(Method::GET, "/api/v1/auth/config", None, None)
        .await;
    assert_eq!(response_json(config).await["passkeysEnabled"], false);
    let session = fixture.login("admin").await;
    for (method, path, body) in [
        (Method::GET, "/api/v1/auth/passkeys", None),
        (
            Method::POST,
            "/api/v1/auth/passkeys/register/options",
            Some(json!({ "password": PASSWORD })),
        ),
        (Method::POST, "/api/v1/auth/passkey/options", None),
        (
            Method::POST,
            "/api/v1/auth/login/passkey/options",
            Some(json!({ "challenge": "anything" })),
        ),
    ] {
        let response = fixture.call(method, path, body, Some(&session)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let enabled = Fixture::new().await;
    let config = enabled
        .call(Method::GET, "/api/v1/auth/config", None, None)
        .await;
    assert_eq!(response_json(config).await["passkeysEnabled"], true);
}

#[tokio::test]
async fn registering_the_first_passkey_issues_recovery_codes_and_signs_out_other_sessions() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let other_session = fixture.login("admin").await;

    let wrong_password = fixture
        .call(
            Method::POST,
            "/api/v1/auth/passkeys/register/options",
            Some(json!({ "password": "not-the-password" })),
            Some(&session),
        )
        .await;
    assert_eq!(wrong_password.status(), StatusCode::FORBIDDEN);
    let signed_out = fixture
        .call(
            Method::POST,
            "/api/v1/auth/passkeys/register/options",
            Some(json!({ "password": PASSWORD })),
            None,
        )
        .await;
    assert_eq!(signed_out.status(), StatusCode::UNAUTHORIZED);

    let options = fixture.register_options(&session).await;
    assert_eq!(options["rp"], json!({ "id": RP_ID, "name": "LightBWS" }));
    assert_eq!(options["user"]["name"], "admin");
    assert_eq!(
        options["user"]["id"],
        encode(fixture.user_id("admin").await.as_bytes())
    );
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(options["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(options["excludeCredentials"], json!([]));
    let challenge = options["challenge"].as_str().unwrap();

    // Another account cannot complete this account's registration.
    let member = fixture.login("member").await;
    let authenticator = SoftwareAuthenticator::new(b"laptop-credential");
    let by_other = fixture
        .register_verify(&member, &authenticator, challenge, "Stolen")
        .await;
    assert_eq!(by_other.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let registered = fixture
        .register_verify(&session, &authenticator, challenge, "  Laptop  ")
        .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered = response_json(registered).await;
    assert_eq!(registered["passkey"]["name"], "Laptop");
    assert_eq!(registered["passkey"]["synced"], false);
    assert_eq!(registered["passkey"]["lastUsedAt"], Value::Null);
    assert_eq!(registered["recoveryCodes"].as_array().unwrap().len(), 10);
    assert!(registered["passkey"].get("publicKey").is_none());

    // The challenge worked once.
    let replayed = fixture
        .register_verify(
            &session,
            &SoftwareAuthenticator::new(b"second"),
            challenge,
            "Again",
        )
        .await;
    assert_eq!(replayed.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let revoked = fixture
        .call(
            Method::GET,
            "/api/v1/auth/session",
            None,
            Some(&other_session),
        )
        .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let current = fixture
        .call(Method::GET, "/api/v1/auth/session", None, Some(&session))
        .await;
    assert_eq!(
        response_json(current).await["user"]["twoFactorEnabled"],
        true
    );
    let status = fixture
        .call(Method::GET, "/api/v1/auth/2fa/status", None, Some(&session))
        .await;
    assert_eq!(
        response_json(status).await,
        json!({ "enabled": true, "totpEnabled": false, "passkeyCount": 1, "recoveryCodesRemaining": 10, "required": false })
    );

    // A second passkey does not replace the recovery codes, and the first one is excluded.
    let options = fixture.register_options(&session).await;
    assert_eq!(
        options["excludeCredentials"],
        json!([{ "type": "public-key", "id": encode(b"laptop-credential"), "transports": ["internal", "hybrid"] }])
    );
    let same_credential = fixture
        .register_verify(
            &session,
            &authenticator,
            options["challenge"].as_str().unwrap(),
            "Duplicate",
        )
        .await;
    assert_eq!(same_credential.status(), StatusCode::CONFLICT);
    let second = fixture
        .register(&session, &SoftwareAuthenticator::new(b"phone"), "Phone")
        .await;
    assert!(second.get("recoveryCodes").is_none());

    let list = fixture
        .call(Method::GET, "/api/v1/auth/passkeys", None, Some(&session))
        .await;
    let list = response_json(list).await;
    assert_eq!(
        list.as_array()
            .unwrap()
            .iter()
            .map(|passkey| passkey["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Laptop", "Phone"]
    );
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.passkey.add'")
            .await,
        2
    );
}

#[tokio::test]
async fn registration_rejects_responses_for_another_site_or_without_user_verification() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let mut authenticator = SoftwareAuthenticator::new(b"credential");
    for case in ["origin", "relying-party", "unverified", "assertion"] {
        let challenge = fixture.register_options(&session).await["challenge"]
            .as_str()
            .unwrap()
            .to_owned();
        authenticator.flags = if case == "unverified" { 0x01 } else { 0x05 };
        let created = match case {
            "origin" => authenticator.create(RP_ID, "https://secrets.example.net", &challenge),
            "relying-party" => authenticator.create("example.net", ORIGIN, &challenge),
            _ => authenticator.create(RP_ID, ORIGIN, &challenge),
        };
        let client_data = if case == "assertion" {
            lightbws::webauthn::testing::client_data("webauthn.get", ORIGIN, &challenge)
        } else {
            created.client_data_json
        };
        let response = fixture
            .call(
                Method::POST,
                "/api/v1/auth/passkeys/register/verify",
                Some(json!({
                    "name": "Key",
                    "credential": {
                        "id": encode(b"credential"),
                        "response": {
                            "clientDataJSON": encode(&client_data),
                            "attestationObject": encode(&created.attestation_object),
                        },
                    },
                })),
                Some(&session),
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{case}"
        );
    }
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_passkeys")
            .await,
        0
    );
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM login_challenges")
            .await,
        0
    );
}

#[tokio::test]
async fn a_passkey_completes_the_step_after_the_password() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let mut authenticator = SoftwareAuthenticator::new(b"laptop");
    fixture.register(&session, &authenticator, "Laptop").await;
    let member = fixture.login("member").await;
    let mut member_authenticator = SoftwareAuthenticator::new(b"member-key");
    fixture
        .register(&member, &member_authenticator, "Member key")
        .await;

    let (challenge, methods) = fixture.challenge("admin").await;
    assert_eq!(methods, json!(["passkey"]));
    let options = fixture
        .call(
            Method::POST,
            "/api/v1/auth/login/passkey/options",
            Some(json!({ "challenge": challenge })),
            None,
        )
        .await;
    assert_eq!(options.status(), StatusCode::OK);
    let options = response_json(options).await["publicKey"].clone();
    assert_eq!(options["challenge"], challenge);
    assert_eq!(options["rpId"], RP_ID);
    assert_eq!(options["allowCredentials"][0]["id"], encode(b"laptop"));
    assert_eq!(options["allowCredentials"].as_array().unwrap().len(), 1);
    let unknown = fixture
        .call(
            Method::POST,
            "/api/v1/auth/login/passkey/options",
            Some(json!({ "challenge": "not-a-challenge" })),
            None,
        )
        .await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);

    // Another user's passkey does not finish this user's sign-in.
    let foreign = member_authenticator.get(RP_ID, ORIGIN, &challenge);
    let refused = fixture
        .second_step(credential(&member_authenticator, &foreign, None))
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    // A second-step challenge is not accepted by the passkey-only route.
    let response = authenticator.get(RP_ID, ORIGIN, &challenge);
    let wrong_route = fixture
        .sign_in(credential(&authenticator, &response, None))
        .await;
    assert_eq!(wrong_route.status(), StatusCode::UNAUTHORIZED);

    let response = authenticator.get(RP_ID, ORIGIN, &challenge);
    let signed_in = fixture
        .second_step(credential(&authenticator, &response, None))
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
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_passkeys WHERE last_used_at IS NOT NULL AND sign_count = 2")
            .await,
        1
    );

    // The challenge is spent, and so is that assertion.
    let again = authenticator.get(RP_ID, ORIGIN, &challenge);
    assert_eq!(
        fixture
            .second_step(credential(&authenticator, &again, None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .second_step(credential(&authenticator, &response, None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Five failed second steps use the challenge up; a recovery code still works on a new one.
    let (challenge, _) = fixture.challenge("admin").await;
    authenticator.honest = false;
    for _ in 0..5 {
        let bad = authenticator.get(RP_ID, ORIGIN, &challenge);
        assert_eq!(
            fixture
                .second_step(credential(&authenticator, &bad, None))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    authenticator.honest = true;
    let late = authenticator.get(RP_ID, ORIGIN, &challenge);
    assert_eq!(
        fixture
            .second_step(credential(&authenticator, &late, None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_passkey_signs_in_on_its_own() {
    let fixture = Fixture::new().await;
    let session = fixture.login("member").await;
    let mut authenticator = SoftwareAuthenticator::new(b"member-phone");
    fixture.register(&session, &authenticator, "Phone").await;
    let member_id = fixture.user_id("member").await;
    let admin_id = fixture.user_id("admin").await;

    let challenge = fixture.sign_in_challenge().await;
    let response = authenticator.get(RP_ID, ORIGIN, &challenge);
    let signed_in = fixture
        .sign_in(credential(
            &authenticator,
            &response,
            Some(member_id.as_bytes()),
        ))
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let (new_session, body) = session_of(signed_in).await;
    assert_eq!(body["user"]["username"], "member");
    assert!(new_session.cookies.contains("lightbws_session="));
    let projects = fixture
        .call(Method::GET, "/api/v1/projects", None, Some(&new_session))
        .await;
    assert_eq!(projects.status(), StatusCode::OK);

    // Replaying the same response, or reusing the challenge, fails.
    assert_eq!(
        fixture
            .sign_in(credential(
                &authenticator,
                &response,
                Some(member_id.as_bytes())
            ))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let reused = authenticator.get(RP_ID, ORIGIN, &challenge);
    assert_eq!(
        fixture
            .sign_in(credential(&authenticator, &reused, None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // A challenge the server never issued.
    let invented = authenticator.get(RP_ID, ORIGIN, &encode(&[5; 32]));
    assert_eq!(
        fixture
            .sign_in(credential(&authenticator, &invented, None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // A passkey-only challenge is not accepted as a registration or as a second step.
    let challenge = fixture.sign_in_challenge().await;
    let as_registration = fixture
        .register_verify(&new_session, &authenticator, &challenge, "Cross")
        .await;
    assert_eq!(as_registration.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let as_second_step = authenticator.get(RP_ID, ORIGIN, &challenge);
    assert_eq!(
        fixture
            .second_step(credential(&authenticator, &as_second_step, None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Each of these is a well-formed response that must not open a session.
    for case in [
        "origin",
        "relying-party",
        "unverified",
        "signature",
        "unknown-credential",
        "user-handle",
        "expired",
    ] {
        let challenge = fixture.sign_in_challenge().await;
        let mut other = SoftwareAuthenticator::new(b"never-registered");
        authenticator.flags = if case == "unverified" { 0x01 } else { 0x05 };
        authenticator.honest = case != "signature";
        if case == "expired" {
            fixture
                .db
                .connection()
                .execute_unprepared("UPDATE login_challenges SET created_at = 0, expires_at = 1")
                .await
                .unwrap();
        }
        let body = match case {
            "origin" => {
                let response = authenticator.get(RP_ID, "https://secrets.example.net", &challenge);
                credential(&authenticator, &response, None)
            }
            "relying-party" => {
                let response = authenticator.get("example.net", ORIGIN, &challenge);
                credential(&authenticator, &response, None)
            }
            "unknown-credential" => {
                let response = other.get(RP_ID, ORIGIN, &challenge);
                credential(&other, &response, None)
            }
            "user-handle" => {
                let response = authenticator.get(RP_ID, ORIGIN, &challenge);
                credential(&authenticator, &response, Some(admin_id.as_bytes()))
            }
            _ => {
                let response = authenticator.get(RP_ID, ORIGIN, &challenge);
                credential(&authenticator, &response, None)
            }
        };
        let refused = fixture.sign_in(body).await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED, "{case}");
        assert!(
            refused.headers().get(header::SET_COOKIE).is_none(),
            "{case}"
        );
    }
    authenticator.flags = 0x05;
    authenticator.honest = true;
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::OK
    );

    // A disabled user is refused exactly like with a password.
    let admin = fixture.login("admin").await;
    let disabled = fixture
        .call(
            Method::PUT,
            &format!("/api/v1/admin/users/{member_id}"),
            Some(json!({ "displayName": "Member", "role": "user", "disabled": true })),
            Some(&admin),
        )
        .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_signature_counter_that_does_not_advance_is_refused_and_audited() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let mut authenticator = SoftwareAuthenticator::new(b"counting-key");
    fixture.register(&session, &authenticator, "Key").await;
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::OK
    );
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::OK
    );

    // A copy of the authenticator made earlier is behind on its counter.
    authenticator.sign_count = 0;
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::UNAUTHORIZED
    );
    authenticator.sign_count = 1;
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM audit_events WHERE action = 'user.passkey.counter_regression' AND outcome = 'denied'")
            .await,
        2
    );
    assert_eq!(
        fixture
            .scalar("SELECT sign_count AS value FROM user_passkeys")
            .await,
        2
    );
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::OK
    );

    // Authenticators that do not count always send zero, which is accepted every time.
    let member = fixture.login("member").await;
    let mut uncounted = SoftwareAuthenticator::new(b"synced-key");
    uncounted.counts = false;
    fixture.register(&member, &uncounted, "Synced").await;
    for _ in 0..2 {
        let challenge = fixture.sign_in_challenge().await;
        let response = uncounted.get(RP_ID, ORIGIN, &challenge);
        assert_eq!(response.authenticator_data[33..37], [0, 0, 0, 0]);
        assert_eq!(
            fixture
                .sign_in(credential(&uncounted, &response, None))
                .await
                .status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn passkeys_can_be_renamed_and_removed_by_their_owner_only() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let mut authenticator = SoftwareAuthenticator::new(b"laptop");
    let registered = fixture.register(&session, &authenticator, "Laptop").await;
    let id = registered["passkey"]["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/auth/passkeys/{id}");
    let member = fixture.login("member").await;

    let by_other = fixture
        .call(
            Method::PUT,
            &path,
            Some(json!({ "name": "Mine now" })),
            Some(&member),
        )
        .await;
    assert_eq!(by_other.status(), StatusCode::NOT_FOUND);
    let empty = fixture
        .call(
            Method::PUT,
            &path,
            Some(json!({ "name": "  " })),
            Some(&session),
        )
        .await;
    assert_eq!(empty.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let renamed = fixture
        .call(
            Method::PUT,
            &path,
            Some(json!({ "name": "Work laptop" })),
            Some(&session),
        )
        .await;
    assert_eq!(renamed.status(), StatusCode::OK);
    assert_eq!(response_json(renamed).await["name"], "Work laptop");

    let remove_by_other = fixture
        .call(
            Method::DELETE,
            &path,
            Some(json!({ "password": PASSWORD })),
            Some(&member),
        )
        .await;
    assert_eq!(remove_by_other.status(), StatusCode::NOT_FOUND);
    let wrong_password = fixture
        .call(
            Method::DELETE,
            &path,
            Some(json!({ "password": "not-the-password" })),
            Some(&session),
        )
        .await;
    assert_eq!(wrong_password.status(), StatusCode::FORBIDDEN);
    let removed = fixture
        .call(
            Method::DELETE,
            &path,
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);

    // The last factor took the recovery codes with it, and sign-in is password-only again.
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_recovery_codes")
            .await,
        0
    );
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::UNAUTHORIZED
    );
    let response = fixture.password_step("admin").await;
    assert!(response.headers().get(header::SET_COOKIE).is_some());
    for action in ["user.passkey.rename", "user.passkey.remove"] {
        assert_eq!(
            fixture
                .scalar(&format!(
                    "SELECT COUNT(*) AS value FROM audit_events WHERE action = '{action}'"
                ))
                .await,
            1
        );
    }
}

#[tokio::test]
async fn passkeys_and_an_authenticator_app_share_recovery_codes_and_policy() {
    let fixture = Fixture::with(Options {
        require_2fa: TwoFactorPolicy::Admins,
        ..Options::default()
    })
    .await;
    // Policy holds the administrator at enrolment; a passkey satisfies it.
    let session = fixture.login("admin").await;
    let held = fixture
        .call(Method::GET, "/api/v1/projects", None, Some(&session))
        .await;
    assert_eq!(held.status(), StatusCode::FORBIDDEN);
    let authenticator = SoftwareAuthenticator::new(b"admin-key");
    let registered = fixture.register(&session, &authenticator, "Key").await;
    let id = registered["passkey"]["id"].as_str().unwrap().to_owned();
    let codes = registered["recoveryCodes"].as_array().unwrap().clone();
    let released = fixture
        .call(Method::GET, "/api/v1/projects", None, Some(&session))
        .await;
    assert_eq!(released.status(), StatusCode::OK);

    // The only factor cannot be removed while policy requires one.
    let path = format!("/api/v1/auth/passkeys/{id}");
    let refused = fixture
        .call(
            Method::DELETE,
            &path,
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_passkeys")
            .await,
        1
    );

    // A passkey-only account regenerates recovery codes with the password alone.
    let regenerated = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/recovery-codes/regenerate",
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    assert_eq!(regenerated.status(), StatusCode::OK);
    let new_codes = response_json(regenerated).await["recoveryCodes"].clone();
    assert_ne!(new_codes, Value::Array(codes));

    // Adding an authenticator app keeps the existing recovery codes working.
    let setup = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/setup",
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    let secret =
        totp::base32_decode(response_json(setup).await["secret"].as_str().unwrap()).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let confirm = fixture
        .call(
            Method::POST,
            "/api/v1/auth/2fa/totp/confirm",
            Some(json!({ "code": totp::code_at(&secret, totp::step_at(now) - 1) })),
            Some(&session),
        )
        .await;
    assert_eq!(confirm.status(), StatusCode::OK);
    let (challenge, methods) = fixture.challenge("admin").await;
    assert_eq!(methods, json!(["totp", "passkey"]));
    let with_code = fixture
        .call(
            Method::POST,
            "/api/v1/auth/login/2fa",
            Some(json!({ "challenge": challenge, "code": totp::code_at(&secret, totp::step_at(now)) })),
            None,
        )
        .await;
    assert_eq!(with_code.status(), StatusCode::OK);

    // With two factors either one can go, and the recovery codes stay with the other.
    let removed = fixture
        .call(
            Method::DELETE,
            &path,
            Some(json!({ "password": PASSWORD })),
            Some(&session),
        )
        .await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fixture
            .scalar("SELECT COUNT(*) AS value FROM user_recovery_codes")
            .await,
        10
    );
    let (_, methods) = fixture.challenge("admin").await;
    assert_eq!(methods, json!(["totp"]));
}

#[tokio::test]
async fn an_administrator_reset_and_break_glass_remove_passkeys() {
    let fixture = Fixture::new().await;
    let member = fixture.login("member").await;
    let mut member_key = SoftwareAuthenticator::new(b"member-key");
    fixture.register(&member, &member_key, "Key").await;
    let admin = fixture.login("admin").await;
    let mut admin_key = SoftwareAuthenticator::new(b"admin-key");
    fixture.register(&admin, &admin_key, "Key").await;

    let users = fixture
        .call(Method::GET, "/api/v1/admin/users", None, Some(&admin))
        .await;
    let users = response_json(users).await;
    assert!(
        users
            .as_array()
            .unwrap()
            .iter()
            .all(|user| user["twoFactorEnabled"] == true)
    );
    let reset = fixture
        .call(
            Method::DELETE,
            &format!(
                "/api/v1/admin/users/{}/2fa",
                fixture.user_id("member").await
            ),
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fixture.sign_in_with(&mut member_key).await,
        StatusCode::UNAUTHORIZED
    );
    let stale = fixture
        .call(Method::GET, "/api/v1/auth/session", None, Some(&member))
        .await;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    assert!(
        break_glass_reset(&fixture.db, &fixture.master_key, "admin")
            .await
            .unwrap()
    );
    assert_eq!(
        fixture.sign_in_with(&mut admin_key).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .scalar("SELECT (SELECT COUNT(*) FROM user_passkeys) + (SELECT COUNT(*) FROM user_recovery_codes) AS value")
            .await,
        0
    );
}

#[tokio::test]
async fn archives_carry_passkeys_and_older_archives_still_import() {
    let fixture = Fixture::new().await;
    let session = fixture.login("admin").await;
    let mut authenticator = SoftwareAuthenticator::new(b"travelling-key");
    fixture.register(&session, &authenticator, "Key").await;
    assert_eq!(
        fixture.sign_in_with(&mut authenticator).await,
        StatusCode::OK
    );

    let dump = dump_database_scoped(
        &fixture.db,
        &fixture.master_key,
        BackupScopes::full_instance(),
    )
    .await
    .expect("dump");
    let archived: Value = serde_json::from_slice(&dump).unwrap();
    assert_eq!(archived["userPasskeys"].as_array().unwrap().len(), 1);
    let secrets_only =
        dump_database_scoped(&fixture.db, &fixture.master_key, BackupScopes::default())
            .await
            .expect("dump");
    let secrets_only: Value = serde_json::from_slice(&secrets_only).unwrap();
    assert!(secrets_only.get("userPasskeys").is_none());

    let target_data = tempfile::tempdir().expect("tempdir");
    let target = Database::connect(&target_data.path().join("target.sqlite3"), key())
        .await
        .expect("target");
    let target_master_key = MasterKey::random().expect("master key");
    import_database_scoped(&target, &target_master_key, &dump, true, false)
        .await
        .expect("restore");
    // Importing twice replaces rather than duplicates.
    import_database_scoped(&target, &target_master_key, &dump, false, false)
        .await
        .expect("merge");
    assert_eq!(
        scalar(&target, "SELECT COUNT(*) AS value FROM user_passkeys").await,
        1
    );
    let restored = Fixture::over(
        target.clone(),
        target_master_key,
        target_data,
        Options::default(),
    );
    assert_eq!(
        restored.sign_in_with(&mut authenticator).await,
        StatusCode::OK
    );
    let (_, methods) = restored.challenge("admin").await;
    assert_eq!(methods, json!(["passkey"]));

    // Restored without a public URL, the account still needs a second step: a recovery code.
    let disabled_data = tempfile::tempdir().expect("tempdir");
    let disabled_db = Database::connect(&disabled_data.path().join("disabled.sqlite3"), key())
        .await
        .expect("target");
    let disabled_key = MasterKey::random().expect("master key");
    import_database_scoped(&disabled_db, &disabled_key, &dump, true, false)
        .await
        .expect("restore");
    let disabled = Fixture::over(
        disabled_db,
        disabled_key,
        disabled_data,
        Options {
            public_url: None,
            ..Options::default()
        },
    );
    let (_, methods) = disabled.challenge("admin").await;
    assert_eq!(methods, json!([]));

    // An archive written before passkeys existed still imports.
    let mut without_section = archived.clone();
    without_section
        .as_object_mut()
        .unwrap()
        .remove("userPasskeys");
    let legacy_data = tempfile::tempdir().expect("tempdir");
    let legacy = Database::connect(&legacy_data.path().join("legacy.sqlite3"), key())
        .await
        .expect("legacy target");
    import_database_scoped(
        &legacy,
        &MasterKey::random().unwrap(),
        &serde_json::to_vec(&without_section).unwrap(),
        true,
        false,
    )
    .await
    .expect("archive without passkeys");
    assert_eq!(
        scalar(&legacy, "SELECT COUNT(*) AS value FROM user_passkeys").await,
        0
    );

    // Passkeys for a user the archive does not contain, or with a malformed key, are rejected.
    for (field, value) in [
        ("user_id", json!(uuid::Uuid::new_v4().to_string())),
        ("public_key", json!("not base64url!")),
        ("sign_count", json!(-1)),
        ("name", json!("")),
    ] {
        let mut forged = archived.clone();
        forged["userPasskeys"][0][field] = value;
        assert!(
            import_database_scoped(
                &legacy,
                &MasterKey::random().unwrap(),
                &serde_json::to_vec(&forged).unwrap(),
                false,
                false,
            )
            .await
            .is_err(),
            "{field}"
        );
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
async fn failed_passkey_sign_ins_are_logged_for_fail2ban_and_rate_limited() {
    use tracing::instrument::WithSubscriber as _;

    let fixture = Fixture::with(Options {
        ip_header: Some(HeaderName::from_static("x-real-ip")),
        ..Options::default()
    })
    .await;
    let session = fixture.login("admin").await;
    let mut authenticator = SoftwareAuthenticator::new(b"logged-key");
    fixture.register(&session, &authenticator, "Key").await;
    let attempt = |path: &'static str, credential: Value, client: &'static str| {
        fixture.request(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-real-ip", client)
                .body(Body::from(json!({ "credential": credential }).to_string()))
                .unwrap(),
        )
    };

    let writer = BufferWriter::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer.clone()),
        )
        .with(EnvFilter::new("lightbws::auth=warn"));
    let run = async {
        // Passkey-only: the account is unknown until a credential matches.
        let challenge = fixture.sign_in_challenge().await;
        let mut stranger = SoftwareAuthenticator::new(b"stranger");
        let response = stranger.get(RP_ID, ORIGIN, &challenge);
        let refused = attempt(
            "/api/v1/auth/passkey/verify",
            credential(&stranger, &response, None),
            "203.0.113.7",
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

        // After the password the account is known.
        let (challenge, _) = fixture.challenge("admin").await;
        authenticator.honest = false;
        let response = authenticator.get(RP_ID, ORIGIN, &challenge);
        let refused = attempt(
            "/api/v1/auth/login/passkey/verify",
            credential(&authenticator, &response, None),
            "203.0.113.8",
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    };
    run.with_subscriber(subscriber).await;
    let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2, "{output}");
    assert!(lines[0].contains(
        r#"WARN lightbws::auth: web login failed ip=203.0.113.7 reason=invalid_passkey username="""#
    ));
    assert!(lines[1].contains(
        r#"WARN lightbws::auth: web login failed ip=203.0.113.8 reason=invalid_passkey username="admin""#
    ));

    // One address is cut off after repeated failures; another is not affected.
    let mut last = StatusCode::OK;
    for _ in 0..31 {
        let challenge = fixture.sign_in_challenge().await;
        let response = authenticator.get(RP_ID, ORIGIN, &challenge);
        last = attempt(
            "/api/v1/auth/passkey/verify",
            credential(&authenticator, &response, None),
            "203.0.113.9",
        )
        .await
        .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    authenticator.honest = true;
    let challenge = fixture.sign_in_challenge().await;
    let response = authenticator.get(RP_ID, ORIGIN, &challenge);
    let elsewhere = attempt(
        "/api/v1/auth/passkey/verify",
        credential(&authenticator, &response, None),
        "203.0.113.10",
    )
    .await;
    assert_eq!(elsewhere.status(), StatusCode::OK);
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
