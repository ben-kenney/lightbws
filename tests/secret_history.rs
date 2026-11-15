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
        audit::AuditActor,
        machines::MachineRepository,
        projects::ProjectRepository,
        secret_history::SecretHistoryRepository,
        secrets::SecretRepository,
        transfer::{BackupScopes, dump_database_scoped, import_database_scoped},
        users::{Role, UserRepository},
    },
    sdk_crypto::{OrganizationKey, legacy},
};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

/// Ciphertext written under the published key that releases before per-instance keys used. It
/// decrypts to `TEST`.
const LEGACY_FIXTURE: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";

struct Fixture {
    _data: TempDir,
    app: Router,
    db: Database,
    admin_id: Uuid,
    member_id: Uuid,
    project_id: Uuid,
    secret_id: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_limit(20).await
    }

    async fn with_limit(limit: u32) -> Self {
        let data = tempfile::tempdir().expect("tempdir");
        let db = Database::connect(&data.path().join("history.sqlite3"), key())
            .await
            .expect("database")
            .with_secret_history_limit(limit);
        let users = UserRepository::new(db.clone());
        let admin = users
            .create("admin", "Administrator", Role::Admin, "test-password-123")
            .await
            .expect("admin");
        let member = users
            .create("member", "Member", Role::User, "test-password-123")
            .await
            .expect("member");
        users
            .create("outsider", "Outsider", Role::User, "test-password-123")
            .await
            .expect("outsider");
        let project = ProjectRepository::new(db.clone())
            .create_sdk("Application")
            .await
            .expect("project");
        let secret = SecretRepository::new(db.clone())
            .create_web("DATABASE_URL", "first-value", "first note", project.id)
            .await
            .expect("secret");
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().into(),
            bootstrap_admin: None,
            cookie_secure: false,
            master_key: None,
            organization_key_file: None,
            ip_header: None,
            log_file: None,
            secret_history_limit: limit,
            allow_plaintext_backups: false,
        };
        Self {
            _data: data,
            app: create_app(AppState::new(db.clone(), &config)),
            db,
            admin_id: admin.id,
            member_id: member.id,
            project_id: project.id,
            secret_id: secret.id,
        }
    }

    async fn request(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.expect("request")
    }

    async fn login(&self, username: &str) -> Session {
        let response = self
            .request(json_request(
                Method::POST,
                "/api/v1/auth/login",
                Some(json!({ "username": username, "password": "test-password-123" })),
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
        Session {
            cookies,
            csrf: body["csrfToken"].as_str().unwrap().to_owned(),
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        session: &Session,
    ) -> axum::response::Response {
        self.request(json_request(method, path, body, Some(session)))
            .await
    }

    async fn update(&self, session: &Session, key: &str, value: &str, note: &str) {
        let response = self
            .call(
                Method::PUT,
                &format!("/api/v1/secrets/{}", self.secret_id),
                Some(json!({
                    "key": key,
                    "value": value,
                    "note": note,
                    "projectId": self.project_id
                })),
                session,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn versions(&self, session: &Session) -> Vec<Value> {
        let response = self
            .call(
                Method::GET,
                &format!("/api/v1/secrets/{}/versions", self.secret_id),
                None,
                session,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await.as_array().unwrap().clone()
    }

    async fn grant_member(&self, admin: &Session, write: bool) {
        let response = self
            .call(
                Method::PUT,
                &format!("/api/v1/secrets/{}/access", self.secret_id),
                Some(json!({
                    "users": [{ "granteeId": self.member_id, "read": true, "write": write }],
                    "groups": [],
                    "machines": []
                })),
                admin,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn audit_count(&self, action: &str) -> i64 {
        scalar(
            &self.db,
            &format!("SELECT COUNT(*) AS value FROM audit_events WHERE action = '{action}'"),
        )
        .await
    }
}

struct Session {
    cookies: String,
    csrf: String,
}

#[tokio::test]
async fn web_updates_record_the_replaced_content_once() {
    let fixture = Fixture::new().await;
    let admin = fixture.login("admin").await;
    assert!(fixture.versions(&admin).await.is_empty());

    fixture
        .update(&admin, "DATABASE_URL", "second-value", "first note")
        .await;
    let versions = fixture.versions(&admin).await;
    assert_eq!(versions.len(), 1);
    let version = &versions[0];
    assert_eq!(version["version"], 1);
    assert_eq!(version["actorKind"], "user");
    assert_eq!(version["actorId"], fixture.admin_id.to_string());
    assert_eq!(version["actorName"], "admin");
    assert_eq!(version["keyChanged"], false);
    assert_eq!(version["valueChanged"], true);
    assert_eq!(version["noteChanged"], false);
    // The list is metadata only.
    let listed = serde_json::to_string(&versions).unwrap();
    for hidden in ["first-value", "second-value", "first note", "DATABASE_URL"] {
        assert!(!listed.contains(hidden), "list must not contain {hidden}");
    }
    assert!(version.get("value").is_none() && version.get("key").is_none());

    // Re-sending identical content encrypts to different ciphertext but changes nothing.
    fixture
        .update(&admin, "DATABASE_URL", "second-value", "first note")
        .await;
    // Moving the secret out of its project changes no content either.
    let moved = fixture
        .call(
            Method::PUT,
            &format!("/api/v1/secrets/{}", fixture.secret_id),
            Some(json!({
                "key": "DATABASE_URL",
                "value": "second-value",
                "note": "first note",
                "projectId": null
            })),
            &admin,
        )
        .await;
    assert_eq!(moved.status(), StatusCode::OK);
    assert_eq!(fixture.versions(&admin).await.len(), 1);

    assert_eq!(fixture.audit_count("secret.version.read").await, 0);
    let detail = fixture
        .call(
            Method::GET,
            &format!("/api/v1/secrets/{}/versions/1", fixture.secret_id),
            None,
            &admin,
        )
        .await;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail = response_json(detail).await;
    assert_eq!(detail["key"], "DATABASE_URL");
    assert_eq!(detail["value"], "first-value");
    assert_eq!(detail["note"], "first note");
    assert_eq!(fixture.audit_count("secret.version.read").await, 1);

    let missing = fixture
        .call(
            Method::GET,
            &format!("/api/v1/secrets/{}/versions/9", fixture.secret_id),
            None,
            &admin,
        )
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // Nothing in the table is stored in the clear.
    let plain_rows = scalar(
        &fixture.db,
        "SELECT COUNT(*) AS value FROM secret_versions WHERE key_plain IS NOT NULL",
    )
    .await;
    assert_eq!(plain_rows, 0);
}

#[tokio::test]
async fn sdk_updates_record_the_replaced_content_and_the_machine() {
    let fixture = Fixture::new().await;
    let machine = MachineRepository::new(fixture.db.clone())
        .issue("deployer", fixture.admin_id)
        .await
        .expect("machine");
    fixture
        .db
        .connection()
        .execute_unprepared(&format!(
            "UPDATE machine_accounts SET compatibility_account = 1 WHERE id = '{}'",
            machine.account.id
        ))
        .await
        .expect("flag machine");
    let (client_id, client_secret) = token_credentials(&machine.access_token);
    let token = fixture
        .request(
            Request::builder()
                .method(Method::POST)
                .uri("/identity/connect/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=client_credentials&scope=api.secrets&client_id={client_id}&client_secret={client_secret}"
                )))
                .unwrap(),
        )
        .await;
    assert_eq!(token.status(), StatusCode::OK);
    let bearer = response_json(token).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let organization_key = fixture.db.organization_key().clone();
    let sdk_update = |key: &str, value: &str, note: &str, value_changed: bool| {
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/api/secrets/{}", fixture.secret_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::from(
                json!({
                    "key": organization_key.encrypt(key).unwrap(),
                    "value": organization_key.encrypt(value).unwrap(),
                    "note": organization_key.encrypt(note).unwrap(),
                    "projectIds": [fixture.project_id],
                    "valueChanged": value_changed
                })
                .to_string(),
            ))
            .unwrap()
    };

    // The client claims nothing changed; the server compares the content itself.
    let changed = fixture
        .request(sdk_update("DATABASE_URL", "sdk-value", "first note", false))
        .await;
    assert_eq!(changed.status(), StatusCode::OK);
    // The client claims a change but re-sends the same content under fresh ciphertext.
    let unchanged = fixture
        .request(sdk_update("DATABASE_URL", "sdk-value", "first note", true))
        .await;
    assert_eq!(unchanged.status(), StatusCode::OK);

    let admin = fixture.login("admin").await;
    let versions = fixture.versions(&admin).await;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["actorKind"], "machine");
    assert_eq!(versions[0]["actorId"], machine.account.id.to_string());
    assert_eq!(versions[0]["actorName"], "deployer");
    let detail = SecretHistoryRepository::new(fixture.db.clone())
        .get(fixture.secret_id, 1)
        .await
        .expect("version");
    assert_eq!(detail.value.as_deref(), Some("first-value"));
}

#[tokio::test]
async fn history_is_bounded_by_the_configured_limit() {
    let fixture = Fixture::with_limit(3).await;
    let admin = fixture.login("admin").await;
    for value in ["v2", "v3", "v4", "v5"] {
        fixture.update(&admin, "DATABASE_URL", value, "note").await;
    }
    let versions = fixture.versions(&admin).await;
    let numbers = versions
        .iter()
        .map(|version| version["version"].as_i64().unwrap())
        .collect::<Vec<_>>();
    // Four changes were made; the oldest version is gone.
    assert_eq!(numbers, [4, 3, 2]);

    let disabled = Fixture::with_limit(0).await;
    let admin = disabled.login("admin").await;
    disabled
        .update(&admin, "DATABASE_URL", "changed", "note")
        .await;
    assert!(disabled.versions(&admin).await.is_empty());
}

#[tokio::test]
async fn restore_is_undoable_audited_and_needs_write_access() {
    let fixture = Fixture::new().await;
    let admin = fixture.login("admin").await;
    fixture
        .update(&admin, "DATABASE_URL", "mistake", "first note")
        .await;

    let member = fixture.login("member").await;
    let outsider = fixture.login("outsider").await;
    let list_path = format!("/api/v1/secrets/{}/versions", fixture.secret_id);
    let read_path = format!("{list_path}/1");
    let restore_path = format!("{list_path}/1/restore");
    for session in [&member, &outsider] {
        for path in [&list_path, &read_path] {
            let denied = fixture.call(Method::GET, path, None, session).await;
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        }
    }
    fixture.grant_member(&admin, false).await;
    let readable = fixture.call(Method::GET, &read_path, None, &member).await;
    assert_eq!(readable.status(), StatusCode::OK);
    let read_only = fixture
        .call(Method::POST, &restore_path, None, &member)
        .await;
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);
    let member_clear = fixture
        .call(Method::DELETE, &list_path, None, &member)
        .await;
    assert_eq!(member_clear.status(), StatusCode::FORBIDDEN);
    // Restore is a mutation and needs the CSRF header.
    let without_csrf = fixture
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(&restore_path)
                .header(header::COOKIE, &admin.cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(without_csrf.status(), StatusCode::FORBIDDEN);

    fixture.grant_member(&admin, true).await;
    let revision_before = scalar(
        &fixture.db,
        "SELECT revision_nanos AS value FROM sdk_sync_state",
    )
    .await;
    let restored = fixture
        .call(Method::POST, &restore_path, None, &member)
        .await;
    assert_eq!(restored.status(), StatusCode::OK);
    let restored = response_json(restored).await;
    assert_eq!(restored["value"], "first-value");
    assert_eq!(restored["projectId"], fixture.project_id.to_string());
    assert_eq!(restored["sdkEncrypted"], true);
    let revision_after = scalar(
        &fixture.db,
        "SELECT revision_nanos AS value FROM sdk_sync_state",
    )
    .await;
    assert!(revision_after > revision_before);
    assert_eq!(fixture.audit_count("secret.version.restore").await, 1);

    // The content the restore replaced is itself a version, attributed to who restored.
    let versions = fixture.versions(&admin).await;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["version"], 2);
    assert_eq!(versions[0]["actorId"], fixture.member_id.to_string());
    let undone = SecretHistoryRepository::new(fixture.db.clone())
        .get(fixture.secret_id, 2)
        .await
        .expect("version");
    assert_eq!(undone.value.as_deref(), Some("mistake"));

    let cleared = fixture.call(Method::DELETE, &list_path, None, &admin).await;
    assert_eq!(cleared.status(), StatusCode::NO_CONTENT);
    assert!(fixture.versions(&admin).await.is_empty());
    assert_eq!(fixture.audit_count("secret.history.clear").await, 1);
}

#[tokio::test]
async fn trash_keeps_history_and_purge_removes_it() {
    let fixture = Fixture::new().await;
    let admin = fixture.login("admin").await;
    fixture
        .update(&admin, "DATABASE_URL", "second", "note")
        .await;
    let secret_path = format!("/api/v1/secrets/{}", fixture.secret_id);
    let trashed = fixture
        .call(Method::DELETE, &secret_path, None, &admin)
        .await;
    assert_eq!(trashed.status(), StatusCode::NO_CONTENT);
    let restored = fixture
        .call(Method::PUT, &format!("{secret_path}/restore"), None, &admin)
        .await;
    assert_eq!(restored.status(), StatusCode::NO_CONTENT);
    assert_eq!(fixture.versions(&admin).await.len(), 1);

    let purged = fixture
        .call(
            Method::DELETE,
            &format!("{secret_path}/purge"),
            None,
            &admin,
        )
        .await;
    assert_eq!(purged.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        scalar(&fixture.db, "SELECT COUNT(*) AS value FROM secret_versions").await,
        0
    );
}

#[tokio::test]
async fn legacy_key_migration_re_encrypts_history() {
    let data = tempfile::tempdir().expect("tempdir");
    let path = data.path().join("legacy.sqlite3");
    {
        let db = Database::connect(&path, key()).await.expect("database");
        let secrets = SecretRepository::new(db.clone());
        let secret = secrets
            .create_web("KEY", "value", "note", None)
            .await
            .expect("secret");
        secrets
            .update_web(secret.id, "KEY", "changed", "note", None)
            .await
            .expect("update");
        db.connection()
            .execute_unprepared(&format!(
                "UPDATE secrets SET key_cipher = '{LEGACY_FIXTURE}', value_cipher = '{LEGACY_FIXTURE}',
                     note_cipher = '{LEGACY_FIXTURE}';
                 UPDATE secret_versions SET key_cipher = '{LEGACY_FIXTURE}',
                     value_cipher = '{LEGACY_FIXTURE}', note_cipher = '{LEGACY_FIXTURE}';
                 UPDATE organizations SET key_check = NULL;"
            ))
            .await
            .expect("downgrade to legacy layout");
        db.connection().clone().close().await.expect("close");
    }

    let instance_key = key();
    let (db, report) = Database::connect_with_report(&path, instance_key.clone())
        .await
        .expect("migrate");
    let report = report.expect("migration report");
    assert_eq!(report.legacy_before, 6);
    assert_eq!(report.reencrypted, 6);
    assert_eq!(report.legacy_after, 0);
    let rows = db
        .connection()
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT key_cipher AS value FROM secret_versions
             UNION ALL SELECT value_cipher FROM secret_versions
             UNION ALL SELECT note_cipher FROM secret_versions",
        ))
        .await
        .expect("history ciphertext");
    assert_eq!(rows.len(), 3);
    for row in rows {
        let value = row.try_get::<String>("", "value").expect("value");
        assert!(legacy::decrypt(&value).is_err());
        assert_eq!(instance_key.decrypt(&value).expect("instance key"), "TEST");
    }
}

#[tokio::test]
async fn archives_carry_history_between_instances_with_different_keys() {
    let master_key = MasterKey::random().expect("master key");
    let source_data = tempfile::tempdir().expect("tempdir");
    let source = Database::connect(&source_data.path().join("source.sqlite3"), key())
        .await
        .expect("source");
    UserRepository::new(source.clone())
        .create("admin", "Administrator", Role::Admin, "test-password-123")
        .await
        .expect("admin");
    let secrets = SecretRepository::new(source.clone());
    let secret = secrets
        .create_web("TOKEN", "one", "note", None)
        .await
        .expect("secret");
    for value in ["two", "three"] {
        secrets
            .update_web(secret.id, "TOKEN", value, "note", None)
            .await
            .expect("update");
    }
    let dump = dump_database_scoped(&source, &master_key, BackupScopes::full_instance())
        .await
        .expect("dump");
    // The archive never carries history under the source instance key or in the clear.
    let archived: Value = serde_json::from_slice(&dump).expect("archive json");
    let archived_versions = archived["secretVersions"].as_array().expect("section");
    assert_eq!(archived_versions.len(), 2);
    for version in archived_versions {
        let cipher = version["valueCipher"].as_str().expect("ciphertext");
        assert!(source.organization_key().decrypt(cipher).is_err());
        assert!(version["valuePlain"].is_null());
    }

    let target_data = tempfile::tempdir().expect("tempdir");
    let target = Database::connect(&target_data.path().join("target.sqlite3"), key())
        .await
        .expect("target");
    // Stale history on the destination must not survive a full replace.
    let stale = SecretRepository::new(target.clone()).acting_as(AuditActor::System);
    let stale_secret = stale
        .create_web("STALE", "old", "", None)
        .await
        .expect("stale secret");
    stale
        .update_web(stale_secret.id, "STALE", "new", "", None)
        .await
        .expect("stale update");
    import_database_scoped(&target, &master_key, &dump, true, false)
        .await
        .expect("replace restore");
    assert_eq!(
        scalar(
            &target,
            &format!(
                "SELECT COUNT(*) AS value FROM secret_versions WHERE secret_id = '{}'",
                stale_secret.id
            )
        )
        .await,
        0
    );
    let history = SecretHistoryRepository::new(target.clone());
    assert_eq!(
        history
            .get(secret.id, 1)
            .await
            .expect("v1")
            .value
            .as_deref(),
        Some("one")
    );
    assert_eq!(
        history
            .get(secret.id, 2)
            .await
            .expect("v2")
            .value
            .as_deref(),
        Some("two")
    );

    // Importing the same archive again is idempotent.
    import_database_scoped(&target, &master_key, &dump, false, false)
        .await
        .expect("merge restore");
    assert_eq!(
        scalar(&target, "SELECT COUNT(*) AS value FROM secret_versions").await,
        2
    );

    // A merge that overwrites newer content keeps what it replaced, attributed to the system.
    SecretRepository::new(target.clone())
        .update_web(secret.id, "TOKEN", "local-edit", "note", None)
        .await
        .expect("local edit");
    let local_versions = scalar(&target, "SELECT COUNT(*) AS value FROM secret_versions").await;
    assert_eq!(local_versions, 3);
    import_database_scoped(&target, &master_key, &dump, false, false)
        .await
        .expect("merge restore over local edit");
    let model = SecretRepository::new(target.clone())
        .get(secret.id)
        .await
        .expect("secret");
    let versions = history.list(&model).await.expect("versions");
    assert_eq!(versions.len(), 4);
    assert_eq!(versions[0].actor_kind, "system");
    assert_eq!(
        history
            .get(secret.id, versions[0].version)
            .await
            .expect("overwritten")
            .value
            .as_deref(),
        Some("local-edit")
    );

    // An archive written before version history existed still imports.
    let mut without_section = archived.clone();
    without_section
        .as_object_mut()
        .unwrap()
        .remove("secretVersions");
    let legacy_data = tempfile::tempdir().expect("tempdir");
    let legacy_target = Database::connect(&legacy_data.path().join("target.sqlite3"), key())
        .await
        .expect("target");
    import_database_scoped(
        &legacy_target,
        &master_key,
        &serde_json::to_vec(&without_section).unwrap(),
        true,
        false,
    )
    .await
    .expect("archive without history");
    assert_eq!(
        scalar(
            &legacy_target,
            "SELECT COUNT(*) AS value FROM secret_versions"
        )
        .await,
        0
    );

    // History for a secret the archive does not contain is rejected.
    let mut forged = archived;
    forged["secretVersions"][0]["secretId"] = json!(Uuid::new_v4().to_string());
    assert!(
        import_database_scoped(
            &legacy_target,
            &master_key,
            &serde_json::to_vec(&forged).unwrap(),
            false,
            false,
        )
        .await
        .is_err()
    );
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

fn json_request(
    method: Method,
    uri: &str,
    body: Option<Value>,
    session: Option<&Session>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(session) = session {
        builder = builder
            .header(header::COOKIE, &session.cookies)
            .header("x-csrf-token", &session.csrf);
    }
    builder
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap()
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

fn key() -> OrganizationKey {
    OrganizationKey::random().expect("organization key")
}

fn token_credentials(access_token: &str) -> (String, String) {
    let mut parts = access_token.splitn(3, '.');
    assert_eq!(parts.next(), Some("0"));
    let id = parts.next().expect("token id").to_owned();
    let secret = parts
        .next()
        .and_then(|rest| rest.split(':').next())
        .expect("client secret")
        .to_owned();
    (id, secret)
}
