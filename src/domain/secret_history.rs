//! Bounded per-secret version history.
//!
//! Every change to a secret's key, value or note stores the content that was replaced, so an
//! accidental edit can be undone. History rows hold secret values and are treated exactly like
//! the `secrets` table: ciphertext stays under the organization key and is never decrypted at
//! rest.

use std::collections::{HashMap, HashSet};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, Statement,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    db::{
        Database,
        entities::{machine_account, secret, secret_version, user},
    },
    domain::{audit::AuditActor, now},
    error::AppError,
    sdk_crypto::OrganizationKey,
};

/// Versions kept per secret unless `LIGHTBWS_SECRET_HISTORY_LIMIT` says otherwise.
pub const DEFAULT_HISTORY_LIMIT: u32 = 20;
/// Upper bound for `LIGHTBWS_SECRET_HISTORY_LIMIT`.
pub const MAX_HISTORY_LIMIT: u32 = 1000;

/// A secret's key, value and note in their stored form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretContent {
    Cipher {
        key: String,
        value: String,
        note: String,
    },
    Plain {
        key: String,
        value: String,
        note: String,
    },
}

/// One field, decrypted when the organization key can read it. Opaque client ciphertext that
/// the key cannot read only ever equals the identical ciphertext.
#[derive(PartialEq, Eq)]
enum Field {
    Readable(String),
    Opaque(String),
}

impl SecretContent {
    pub fn of_secret(model: &secret::Model) -> Result<Self, AppError> {
        Self::from_columns(
            (&model.key_cipher, &model.value_cipher, &model.note_cipher),
            (&model.key_plain, &model.value_plain, &model.note_plain),
        )
    }

    pub fn of_version(model: &secret_version::Model) -> Result<Self, AppError> {
        Self::from_columns(
            (&model.key_cipher, &model.value_cipher, &model.note_cipher),
            (&model.key_plain, &model.value_plain, &model.note_plain),
        )
    }

    pub(crate) fn from_columns(
        cipher: (&Option<String>, &Option<String>, &Option<String>),
        plain: (&Option<String>, &Option<String>, &Option<String>),
    ) -> Result<Self, AppError> {
        match (cipher, plain) {
            ((Some(key), Some(value), Some(note)), (None, None, None)) => Ok(Self::Cipher {
                key: key.clone(),
                value: value.clone(),
                note: note.clone(),
            }),
            ((None, None, None), (Some(key), Some(value), Some(note))) => Ok(Self::Plain {
                key: key.clone(),
                value: value.clone(),
                note: note.clone(),
            }),
            _ => Err(AppError::internal(anyhow::anyhow!(
                "secret content is neither ciphertext nor plaintext"
            ))),
        }
    }

    pub fn is_cipher(&self) -> bool {
        matches!(self, Self::Cipher { .. })
    }

    fn fields(&self, organization_key: &OrganizationKey) -> [Field; 3] {
        match self {
            Self::Plain { key, value, note } => [
                Field::Readable(key.trim().to_owned()),
                Field::Readable(value.clone()),
                Field::Readable(note.clone()),
            ],
            Self::Cipher { key, value, note } => [key, value, note].map(|cipher| {
                organization_key
                    .decrypt(cipher)
                    .map_or_else(|_| Field::Opaque(cipher.clone()), Field::Readable)
            }),
        }
    }

    /// Which of key, value and note differ. Encryption is randomised, so ciphertext is compared
    /// by its plaintext whenever the organization key can read it.
    fn differences(&self, other: &Self, organization_key: &OrganizationKey) -> [bool; 3] {
        let (mine, theirs) = (
            self.fields(organization_key),
            other.fields(organization_key),
        );
        [
            mine[0] != theirs[0],
            mine[1] != theirs[1],
            mine[2] != theirs[2],
        ]
    }

    pub fn same_as(&self, other: &Self, organization_key: &OrganizationKey) -> bool {
        self.differences(other, organization_key) == [false; 3]
    }

    /// The content converted to the storage mode of `current`, so restoring an old version never
    /// silently turns an SDK-visible secret into a web-only one or the reverse.
    pub(crate) fn in_mode_of(
        self,
        current: &Self,
        organization_key: &OrganizationKey,
    ) -> Result<Self, AppError> {
        match (self, current.is_cipher()) {
            (Self::Plain { key, value, note }, true) => Ok(Self::Cipher {
                key: organization_key.encrypt(key.trim())?,
                value: organization_key.encrypt(&value)?,
                note: organization_key.encrypt(&note)?,
            }),
            (Self::Cipher { key, value, note }, false) => {
                let unreadable =
                    |_| AppError::Validation("this version cannot be decrypted".into());
                Ok(Self::Plain {
                    key: organization_key.decrypt(&key).map_err(unreadable)?,
                    value: organization_key.decrypt(&value).map_err(unreadable)?,
                    note: organization_key.decrypt(&note).map_err(unreadable)?,
                })
            }
            (content, _) => Ok(content),
        }
    }

    pub(crate) fn apply(self, active: &mut secret::ActiveModel) {
        let (cipher, plain) = match self {
            Self::Cipher { key, value, note } => (Some((key, value, note)), None),
            Self::Plain { key, value, note } => (None, Some((key, value, note))),
        };
        let (key_cipher, value_cipher, note_cipher) = unzip(cipher);
        let (key_plain, value_plain, note_plain) = unzip(plain);
        active.key_cipher = Set(key_cipher);
        active.value_cipher = Set(value_cipher);
        active.note_cipher = Set(note_cipher);
        active.key_plain = Set(key_plain);
        active.value_plain = Set(value_plain);
        active.note_plain = Set(note_plain);
    }
}

fn unzip(
    value: Option<(String, String, String)>,
) -> (Option<String>, Option<String>, Option<String>) {
    match value {
        Some((key, value, note)) => (Some(key), Some(value), Some(note)),
        None => (None, None, None),
    }
}

fn actor_columns(actor: AuditActor) -> (&'static str, Option<String>) {
    match actor {
        AuditActor::User(id) => ("user", Some(id.to_string())),
        AuditActor::Machine(id) => ("machine", Some(id.to_string())),
        AuditActor::System => ("system", None),
    }
}

/// Stores the content of `existing` as the next version of that secret when `replacement`
/// changes its key, value or note, then drops versions beyond `limit` (oldest first). Call it
/// inside the transaction that applies the replacement. Returns whether a version was stored.
///
/// A `limit` of zero records nothing and leaves existing history alone.
pub(crate) async fn record_replaced(
    connection: &impl ConnectionTrait,
    existing: &secret::Model,
    replacement: &SecretContent,
    organization_key: &OrganizationKey,
    actor: AuditActor,
    limit: u32,
) -> Result<bool, AppError> {
    if limit == 0 {
        return Ok(false);
    }
    let current = SecretContent::of_secret(existing)?;
    if current.same_as(replacement, organization_key) {
        return Ok(false);
    }
    let latest = secret_version::Entity::find()
        .select_only()
        .column_as(secret_version::Column::Version.max(), "latest")
        .filter(secret_version::Column::SecretId.eq(existing.id.clone()))
        .into_tuple::<Option<i64>>()
        .one(connection)
        .await?
        .flatten()
        .unwrap_or(0);
    let (actor_kind, actor_id) = actor_columns(actor);
    secret_version::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        secret_id: Set(existing.id.clone()),
        version: Set(latest + 1),
        project_id: Set(existing.project_id.clone()),
        key_cipher: Set(existing.key_cipher.clone()),
        value_cipher: Set(existing.value_cipher.clone()),
        note_cipher: Set(existing.note_cipher.clone()),
        key_plain: Set(existing.key_plain.clone()),
        value_plain: Set(existing.value_plain.clone()),
        note_plain: Set(existing.note_plain.clone()),
        actor_kind: Set(actor_kind.into()),
        actor_id: Set(actor_id),
        valid_from: Set(existing.updated_at),
        replaced_at: Set(now().max(existing.updated_at)),
    }
    .insert(connection)
    .await?;
    prune(connection, &existing.id, limit).await?;
    Ok(true)
}

/// Deletes all but the newest `limit` versions of one secret.
pub(crate) async fn prune(
    connection: &impl ConnectionTrait,
    secret_id: &str,
    limit: u32,
) -> Result<(), AppError> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            r#"
            DELETE FROM secret_versions
            WHERE secret_id = ?
              AND version NOT IN (
                SELECT version FROM secret_versions
                WHERE secret_id = ?
                ORDER BY version DESC
                LIMIT ?
              )
            "#,
            [secret_id.into(), secret_id.into(), i64::from(limit).into()],
        ))
        .await?;
    Ok(())
}

/// What a history list shows for one version. It never carries key, value or note.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVersionSummary {
    pub version: i64,
    pub project_id: Option<Uuid>,
    /// Who made the change that replaced this version.
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub actor_name: Option<String>,
    pub valid_from: i64,
    pub replaced_at: i64,
    /// Whether the field differs from the next newer version, or from the current secret for
    /// the newest version.
    pub key_changed: bool,
    pub value_changed: bool,
    pub note_changed: bool,
}

/// The decrypted content of one version.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVersionDetail {
    pub version: i64,
    pub key: String,
    pub value: Option<String>,
    pub note: String,
    pub valid_from: i64,
    pub replaced_at: i64,
}

#[derive(Clone)]
pub struct SecretHistoryRepository {
    db: Database,
}

impl SecretHistoryRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Versions of `secret`, newest first.
    pub async fn list(
        &self,
        secret: &secret::Model,
    ) -> Result<Vec<SecretVersionSummary>, AppError> {
        let versions = secret_version::Entity::find()
            .filter(secret_version::Column::SecretId.eq(secret.id.clone()))
            .order_by_desc(secret_version::Column::Version)
            .all(self.db.connection())
            .await?;
        let names = self.actor_names(&versions).await?;
        let organization_key = self.db.organization_key();
        let mut newer = SecretContent::of_secret(secret)?;
        let mut summaries = Vec::with_capacity(versions.len());
        for model in versions {
            let content = SecretContent::of_version(&model)?;
            let [key_changed, value_changed, note_changed] =
                content.differences(&newer, organization_key);
            newer = content;
            summaries.push(SecretVersionSummary {
                version: model.version,
                project_id: model
                    .project_id
                    .as_deref()
                    .map(|id| Uuid::parse_str(id).map_err(AppError::internal))
                    .transpose()?,
                actor_name: model
                    .actor_id
                    .as_ref()
                    .and_then(|id| names.get(&(model.actor_kind.clone(), id.clone())).cloned()),
                actor_id: model
                    .actor_id
                    .as_deref()
                    .map(|id| Uuid::parse_str(id).map_err(AppError::internal))
                    .transpose()?,
                actor_kind: model.actor_kind,
                valid_from: model.valid_from,
                replaced_at: model.replaced_at,
                key_changed,
                value_changed,
                note_changed,
            });
        }
        Ok(summaries)
    }

    pub async fn get(
        &self,
        secret_id: Uuid,
        version: i64,
    ) -> Result<SecretVersionDetail, AppError> {
        let model = find_version(self.db.connection(), secret_id, version).await?;
        let organization_key = self.db.organization_key();
        let (key, value, note) = match SecretContent::of_version(&model)? {
            SecretContent::Plain { key, value, note } => (key, Some(value), note),
            SecretContent::Cipher { key, value, note } => (
                organization_key
                    .decrypt(&key)
                    .unwrap_or_else(|_| "Encrypted SDK secret".into()),
                organization_key.decrypt(&value).ok(),
                organization_key.decrypt(&note).unwrap_or_default(),
            ),
        };
        Ok(SecretVersionDetail {
            version: model.version,
            key,
            value,
            note,
            valid_from: model.valid_from,
            replaced_at: model.replaced_at,
        })
    }

    /// Deletes every stored version of one secret and returns how many were removed.
    pub async fn clear(&self, secret_id: Uuid) -> Result<u64, AppError> {
        Ok(secret_version::Entity::delete_many()
            .filter(secret_version::Column::SecretId.eq(secret_id.to_string()))
            .exec(self.db.connection())
            .await?
            .rows_affected)
    }

    async fn actor_names(
        &self,
        versions: &[secret_version::Model],
    ) -> Result<HashMap<(String, String), String>, AppError> {
        let ids = |kind: &str| {
            versions
                .iter()
                .filter(|version| version.actor_kind == kind)
                .filter_map(|version| version.actor_id.clone())
                .collect::<HashSet<_>>()
        };
        let mut names = HashMap::new();
        let users = ids("user");
        if !users.is_empty() {
            for model in user::Entity::find()
                .filter(user::Column::Id.is_in(users))
                .all(self.db.connection())
                .await?
            {
                names.insert(("user".to_owned(), model.id), model.username);
            }
        }
        let machines = ids("machine");
        if !machines.is_empty() {
            for model in machine_account::Entity::find()
                .filter(machine_account::Column::Id.is_in(machines))
                .all(self.db.connection())
                .await?
            {
                names.insert(("machine".to_owned(), model.id), model.name);
            }
        }
        Ok(names)
    }
}

pub(crate) async fn find_version(
    connection: &impl ConnectionTrait,
    secret_id: Uuid,
    version: i64,
) -> Result<secret_version::Model, AppError> {
    secret_version::Entity::find()
        .filter(secret_version::Column::SecretId.eq(secret_id.to_string()))
        .filter(secret_version::Column::Version.eq(version))
        .one(connection)
        .await?
        .ok_or(AppError::NotFound)
}
