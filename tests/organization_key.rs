use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use lightbws::{
    AppState,
    config::Config,
    create_app,
    crypto::MasterKey,
    db::{Database, KeyMigrationReport},
    domain::{
        machines::MachineRepository,
        projects::ProjectRepository,
        secrets::SecretRepository,
        transfer::{BackupScopes, dump_database_scoped, import_database_scoped},
        users::{Role, UserRepository},
    },
    sdk_crypto::{OrganizationKey, legacy, unwrap_access_token_payload},
};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde_json::Value;
use tower::ServiceExt;

/// Ciphertext from the official Bitwarden SDK fixtures, written under the published key that
/// every earlier LightBWS release used. It decrypts to `TEST`.
const LEGACY_FIXTURE: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";

fn key() -> OrganizationKey {
    OrganizationKey::random().expect("organization key")
}

fn config(data: &tempfile::TempDir) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.path().into(),
        bootstrap_admin: None,
        cookie_secure: false,
        allow_plaintext_backups: false,
        master_key: None,
        organization_key_file: None,
    }
}

async fn ciphers(db: &Database) -> Vec<String> {
    let rows = db
        .connection()
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name_cipher AS value FROM projects WHERE name_cipher IS NOT NULL
             UNION ALL SELECT key_cipher FROM secrets WHERE key_cipher IS NOT NULL
             UNION ALL SELECT value_cipher FROM secrets WHERE value_cipher IS NOT NULL
             UNION ALL SELECT note_cipher FROM secrets WHERE note_cipher IS NOT NULL",
        ))
        .await
        .expect("ciphers");
    rows.into_iter()
        .map(|row| row.try_get::<String>("", "value").expect("value"))
        .collect()
}

/// Builds a database in the shape the previous release left behind: SDK columns written under
/// the published legacy key, an access token without a wrapped payload, and no key binding.
async fn legacy_database(path: &std::path::Path) {
    let db = Database::connect(path, key()).await.expect("database");
    let admin = UserRepository::new(db.clone())
        .create("admin", "Administrator", Role::Admin, "test-password-123")
        .await
        .expect("admin");
    let project = ProjectRepository::new(db.clone())
        .create_sdk("Production")
        .await
        .expect("project");
    SecretRepository::new(db.clone())
        .create_web("KEY", "value", "note", project.id)
        .await
        .expect("secret");
    MachineRepository::new(db.clone())
        .issue("Deployment", admin.id)
        .await
        .expect("machine");
    db.connection()
        .execute_unprepared(&format!(
            "UPDATE projects SET name_cipher = '{LEGACY_FIXTURE}';
             UPDATE secrets SET key_cipher = '{LEGACY_FIXTURE}', value_cipher = '{LEGACY_FIXTURE}',
                 note_cipher = '{LEGACY_FIXTURE}';
             UPDATE machine_access_tokens SET encrypted_payload = NULL;
             UPDATE organizations SET key_check = NULL;"
        ))
        .await
        .expect("downgrade to legacy layout");
    db.connection().clone().close().await.expect("close");
}

#[tokio::test]
async fn legacy_database_migrates_once_and_reports_counts() {
    let data = tempfile::tempdir().expect("tempdir");
    let path = data.path().join("legacy.sqlite3");
    legacy_database(&path).await;
    assert!(!Database::has_organization_key(&path).await.expect("probe"));

    let instance_key = key();
    let (db, report) = Database::connect_with_report(&path, instance_key.clone())
        .await
        .expect("migrate");
    assert_eq!(
        report,
        Some(KeyMigrationReport {
            legacy_before: 4,
            reencrypted: 4,
            legacy_after: 0,
            unreadable: 0,
            revoked_access_tokens: 1,
        })
    );
    let values = ciphers(&db).await;
    assert_eq!(values.len(), 4);
    for value in &values {
        assert!(
            legacy::decrypt(value).is_err(),
            "legacy key must no longer decrypt"
        );
        assert_eq!(instance_key.decrypt(value).expect("instance key"), "TEST");
    }
    let tokens = db
        .connection()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS revoked FROM machine_access_tokens WHERE revoked_at IS NOT NULL",
        ))
        .await
        .expect("query")
        .expect("row")
        .try_get::<i64>("", "revoked")
        .expect("count");
    assert_eq!(tokens, 1);
    db.connection().clone().close().await.expect("close");

    assert!(Database::has_organization_key(&path).await.expect("probe"));
    let (_db, report) = Database::connect_with_report(&path, instance_key)
        .await
        .expect("reopen with the same key");
    assert_eq!(report, None);
}

#[tokio::test]
async fn offline_decryption_needs_the_keyfile() {
    // Control: the published constants decrypt the previous release's data.
    assert_eq!(
        legacy::decrypt(LEGACY_FIXTURE).expect("legacy control"),
        "TEST"
    );

    let data = tempfile::tempdir().expect("tempdir");
    let keyfile = data.path().join("keys").join("organization.key");
    let path = data.path().join("data").join("instance.sqlite3");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    legacy_database(&path).await;
    let instance_key = key();
    instance_key.write_new(&keyfile).expect("keyfile");
    let db = Database::connect(&path, instance_key)
        .await
        .expect("migrate");
    let values = ciphers(&db).await;
    db.connection().clone().close().await.expect("close");

    // Without the keyfile: neither the published key nor a fresh key can read a stolen copy.
    let guess = key();
    for value in &values {
        assert!(legacy::decrypt(value).is_err());
        assert!(guess.decrypt(value).is_err());
    }
    // With the keyfile: everything decrypts.
    let loaded = OrganizationKey::load(&keyfile).expect("load keyfile");
    for value in &values {
        assert_eq!(loaded.decrypt(value).expect("keyfile decrypts"), "TEST");
    }
}

#[tokio::test]
async fn database_refuses_a_different_installation_key() {
    let data = tempfile::tempdir().expect("tempdir");
    let path = data.path().join("bound.sqlite3");
    let first = key();
    let db = Database::connect(&path, first.clone()).await.expect("bind");
    let project = ProjectRepository::new(db.clone())
        .create_sdk("Production")
        .await
        .expect("project");
    db.connection().clone().close().await.expect("close");

    let error = Database::connect(&path, key())
        .await
        .err()
        .expect("a different key must be refused");
    assert!(error.to_string().contains("does not match"));

    let other_data = tempfile::tempdir().expect("tempdir");
    let other = Database::connect(&other_data.path().join("other.sqlite3"), key())
        .await
        .expect("second installation");
    assert_ne!(other.organization_key().fingerprint(), first.fingerprint());
    let db = Database::connect(&path, first).await.expect("reopen");
    let cipher = ProjectRepository::new(db.clone())
        .get(project.id)
        .await
        .expect("project")
        .name_cipher
        .expect("cipher");
    assert!(other.organization_key().decrypt(&cipher).is_err());
    assert_eq!(
        db.organization_key().decrypt(&cipher).unwrap(),
        "Production"
    );
}

#[tokio::test]
async fn sdk_login_returns_the_instance_key_wrapped_for_that_token() {
    let data = tempfile::tempdir().expect("tempdir");
    let db = Database::connect(&data.path().join("login.sqlite3"), key())
        .await
        .expect("database");
    let admin = UserRepository::new(db.clone())
        .create("admin", "Administrator", Role::Admin, "test-password-123")
        .await
        .expect("admin");
    let machines = MachineRepository::new(db.clone());
    let first = machines
        .issue("Deployment", admin.id)
        .await
        .expect("machine");
    let second = machines
        .issue_access_token(first.account.id, "Second", None)
        .await
        .expect("second token");
    let app = create_app(AppState::new(db.clone(), &config(&data)));

    let mut access_keys = Vec::new();
    for access_token in [&first.access_token, &second.access_token] {
        let (credential, access_key) = access_token.split_once(':').expect("token halves");
        assert_eq!(STANDARD.decode(access_key).expect("base64").len(), 16);
        let mut parts = credential.splitn(3, '.');
        assert_eq!(parts.next(), Some("0"));
        let client_id = parts.next().expect("id");
        let client_secret = parts.next().expect("secret");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/identity/connect/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=client_credentials&scope=api.secrets&client_id={client_id}&client_secret={client_secret}"
                    )))
                    .unwrap(),
            )
            .await
            .expect("login");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
        )
        .expect("json");
        let payload = body["encrypted_payload"].as_str().expect("payload");
        let unwrapped = unwrap_access_token_payload(access_key, payload).expect("unwrap");
        assert_eq!(unwrapped.fingerprint(), db.organization_key().fingerprint());
        access_keys.push(access_key.to_owned());
    }
    assert_ne!(access_keys[0], access_keys[1]);
    let serialized = format!("{first:?}{second:?}");
    assert!(!serialized.contains("X8vbvA0bduihIDe/qrzIQQ=="));
}

#[tokio::test]
async fn restoring_into_a_different_key_revokes_machine_tokens() {
    let source_data = tempfile::tempdir().expect("tempdir");
    let source = Database::connect(&source_data.path().join("source.sqlite3"), key())
        .await
        .expect("source");
    let admin = UserRepository::new(source.clone())
        .create("admin", "Administrator", Role::Admin, "test-password-123")
        .await
        .expect("admin");
    let project = ProjectRepository::new(source.clone())
        .create_sdk("Production")
        .await
        .expect("project");
    MachineRepository::new(source.clone())
        .issue("Deployment", admin.id)
        .await
        .expect("machine");
    let master_key = MasterKey::random().expect("master key");
    let dump = dump_database_scoped(&source, &master_key, BackupScopes::full_instance())
        .await
        .expect("dump");

    let target_data = tempfile::tempdir().expect("tempdir");
    let target = Database::connect(&target_data.path().join("target.sqlite3"), key())
        .await
        .expect("target");
    let summary = import_database_scoped(&target, &master_key, &dump, true, false)
        .await
        .expect("restore");
    assert_eq!(summary.revoked_access_tokens, 1);
    assert_eq!(summary.unreadable_sdk_values, 0);
    let foreign_payloads = target
        .connection()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS kept FROM machine_access_tokens WHERE encrypted_payload IS NOT NULL",
        ))
        .await
        .expect("query")
        .expect("row")
        .try_get::<i64>("", "kept")
        .expect("count");
    assert_eq!(foreign_payloads, 0, "source wrapped keys must not be kept");
    let cipher = ProjectRepository::new(target.clone())
        .get(project.id)
        .await
        .expect("project")
        .name_cipher
        .expect("cipher");
    assert_eq!(
        target.organization_key().decrypt(&cipher).unwrap(),
        "Production"
    );
    assert!(source.organization_key().decrypt(&cipher).is_err());
}

#[tokio::test]
async fn import_counts_well_formed_ciphertext_it_cannot_decrypt() {
    let source_data = tempfile::tempdir().expect("tempdir");
    let source = Database::connect(&source_data.path().join("source.sqlite3"), key())
        .await
        .expect("source");
    ProjectRepository::new(source.clone())
        .create_sdk("Readable")
        .await
        .expect("project");
    ProjectRepository::new(source.clone())
        .create_sdk("Damaged")
        .await
        .expect("project");
    let master_key = MasterKey::random().expect("master key");
    let dump = dump_database_scoped(&source, &master_key, BackupScopes::default())
        .await
        .expect("dump");
    let mut dump: Value = serde_json::from_slice(&dump).expect("json");
    // One value written under an unrelated key, one opaque non-EncString value.
    dump["projects"][0]["nameCipher"] = Value::String(key().encrypt("lost").expect("encrypt"));
    dump["projects"][1]["nameCipher"] = Value::String("2.opaque-client-data".into());
    let dump = serde_json::to_vec(&dump).expect("serialize");

    let target_data = tempfile::tempdir().expect("tempdir");
    let target = Database::connect(&target_data.path().join("target.sqlite3"), key())
        .await
        .expect("target");
    let summary = import_database_scoped(&target, &master_key, &dump, false, false)
        .await
        .expect("import keeps going");
    assert_eq!(summary.projects, 2);
    assert_eq!(summary.unreadable_sdk_values, 1);
}
