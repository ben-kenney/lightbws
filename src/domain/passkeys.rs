//! Passkeys (WebAuthn credentials) registered by web users. A passkey counts as a second
//! factor, and one used with user verification can also sign in on its own.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Statement, TransactionTrait,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    db::{Database, entities::user_passkey},
    domain::{now, two_factor},
    error::AppError,
    webauthn::{Assertion, Registration},
};

/// Challenge kind for adding a passkey to a signed-in account.
pub const REGISTER_CHALLENGE: &str = "passkey_register";
/// Challenge kind for signing in with a passkey alone.
pub const LOGIN_CHALLENGE: &str = "passkey_login";
pub const MAX_PASSKEYS_PER_USER: u64 = 20;
const MAX_NAME_CHARS: usize = 128;
const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicPasskey {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// The credential is synced between the user's devices rather than bound to one.
    pub synced: bool,
}

impl From<user_passkey::Model> for PublicPasskey {
    fn from(model: user_passkey::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            created_at: model.created_at,
            last_used_at: model.last_used_at,
            synced: model.backup_state,
        }
    }
}

/// What a browser needs to address one credential.
pub struct CredentialDescriptor {
    pub id: String,
    pub transports: Vec<String>,
}

#[derive(Clone)]
pub struct PasskeyRepository {
    db: Database,
}

impl PasskeyRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list(&self, user_id: Uuid) -> Result<Vec<PublicPasskey>, AppError> {
        Ok(self
            .models(user_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub async fn descriptors(&self, user_id: Uuid) -> Result<Vec<CredentialDescriptor>, AppError> {
        Ok(self
            .models(user_id)
            .await?
            .into_iter()
            .map(|model| CredentialDescriptor {
                transports: model
                    .transports
                    .as_deref()
                    .and_then(|value| serde_json::from_str(value).ok())
                    .unwrap_or_default(),
                id: model.credential_id,
            })
            .collect())
    }

    async fn models(&self, user_id: Uuid) -> Result<Vec<user_passkey::Model>, AppError> {
        Ok(user_passkey::Entity::find()
            .filter(user_passkey::Column::UserId.eq(user_id.to_string()))
            .order_by_asc(user_passkey::Column::CreatedAt)
            .order_by_asc(user_passkey::Column::Id)
            .all(self.db.connection())
            .await?)
    }

    /// Stores a verified credential. When it is the user's first second factor, a set of
    /// recovery codes is issued with it and returned.
    pub async fn register(
        &self,
        user_id: Uuid,
        name: &str,
        registration: &Registration,
        transports: &[String],
    ) -> Result<(PublicPasskey, Option<Vec<String>>), AppError> {
        let name = validate_name(name)?;
        let transports = transports
            .iter()
            .filter(|transport| TRANSPORTS.contains(&transport.as_str()))
            .collect::<Vec<_>>();
        let credential_id = URL_SAFE_NO_PAD.encode(&registration.credential_id);
        let transaction = self.db.connection().begin().await?;
        let owned = user_passkey::Entity::find()
            .filter(user_passkey::Column::UserId.eq(user_id.to_string()))
            .count(&transaction)
            .await?;
        if owned >= MAX_PASSKEYS_PER_USER {
            return Err(AppError::Validation(format!(
                "an account can have at most {MAX_PASSKEYS_PER_USER} passkeys"
            )));
        }
        if user_passkey::Entity::find()
            .filter(user_passkey::Column::CredentialId.eq(&credential_id))
            .one(&transaction)
            .await?
            .is_some()
        {
            return Err(AppError::Conflict);
        }
        let first_factor = !two_factor::is_enabled(&transaction, &user_id.to_string()).await?;
        let model = user_passkey::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            credential_id: Set(credential_id),
            public_key: Set(URL_SAFE_NO_PAD.encode(&registration.public_key)),
            sign_count: Set(i64::from(registration.sign_count)),
            transports: Set((!transports.is_empty())
                .then(|| serde_json::to_string(&transports).map_err(AppError::internal))
                .transpose()?),
            backup_eligible: Set(registration.backup_eligible),
            backup_state: Set(registration.backup_eligible && registration.backup_state),
            name: Set(name),
            created_at: Set(now()),
            last_used_at: Set(None),
        }
        .insert(&transaction)
        .await?;
        let recovery_codes = if first_factor {
            Some(two_factor::replace_recovery_codes(&transaction, user_id).await?)
        } else {
            None
        };
        transaction.commit().await?;
        Ok((model.into(), recovery_codes))
    }

    pub async fn rename(
        &self,
        user_id: Uuid,
        id: Uuid,
        name: &str,
    ) -> Result<PublicPasskey, AppError> {
        let name = validate_name(name)?;
        let model = self.owned(user_id, id).await?;
        let mut active: user_passkey::ActiveModel = model.into();
        active.name = Set(name);
        Ok(active.update(self.db.connection()).await?.into())
    }

    /// Removes a passkey. `keep_last_factor` refuses when it is the user's only second factor.
    /// Recovery codes go with the last factor.
    pub async fn remove(
        &self,
        user_id: Uuid,
        id: Uuid,
        keep_last_factor: bool,
    ) -> Result<(), AppError> {
        let transaction = self.db.connection().begin().await?;
        let deleted = user_passkey::Entity::delete_many()
            .filter(user_passkey::Column::Id.eq(id.to_string()))
            .filter(user_passkey::Column::UserId.eq(user_id.to_string()))
            .exec(&transaction)
            .await?;
        if deleted.rows_affected != 1 {
            return Err(AppError::NotFound);
        }
        if !two_factor::is_enabled(&transaction, &user_id.to_string()).await? {
            if keep_last_factor {
                // Dropping the transaction keeps the passkey.
                return Err(AppError::Validation(
                    "two-factor authentication is required for this account".into(),
                ));
            }
            two_factor::delete_recovery_codes(&transaction, user_id).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn find_by_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<user_passkey::Model>, AppError> {
        Ok(user_passkey::Entity::find()
            .filter(user_passkey::Column::CredentialId.eq(credential_id))
            .one(self.db.connection())
            .await?)
    }

    /// Records a verified sign-in. Returns `false`, changing nothing, when the authenticator's
    /// signature counter did not advance, which is what a cloned authenticator looks like.
    /// Authenticators that do not count always report zero.
    pub async fn record_use(
        &self,
        passkey: &user_passkey::Model,
        assertion: &Assertion,
    ) -> Result<bool, AppError> {
        let received = i64::from(assertion.sign_count);
        // The guard also settles two requests racing with the same counter value.
        let updated = self
            .db
            .connection()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE user_passkeys SET sign_count = ?, last_used_at = MAX(?, created_at), \
                 backup_state = ? \
                 WHERE id = ? AND ((sign_count = 0 AND ? = 0) OR sign_count < ?)",
                [
                    received.into(),
                    now().into(),
                    (passkey.backup_eligible && assertion.backup_state).into(),
                    passkey.id.clone().into(),
                    received.into(),
                    received.into(),
                ],
            ))
            .await?;
        Ok(updated.rows_affected() == 1)
    }

    async fn owned(&self, user_id: Uuid, id: Uuid) -> Result<user_passkey::Model, AppError> {
        user_passkey::Entity::find_by_id(id.to_string())
            .one(self.db.connection())
            .await?
            .filter(|model| model.user_id == user_id.to_string())
            .ok_or(AppError::NotFound)
    }
}

/// How many passkeys a user has.
pub async fn count(connection: &impl ConnectionTrait, user_id: &str) -> Result<u64, AppError> {
    Ok(user_passkey::Entity::find()
        .filter(user_passkey::Column::UserId.eq(user_id))
        .count(connection)
        .await?)
}

/// Checks an archived passkey row before it is imported.
pub(crate) fn validate_record(model: &user_passkey::Model) -> bool {
    let decodes = |value: &str, max: usize| {
        URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= max)
    };
    Uuid::parse_str(&model.id).is_ok()
        && decodes(&model.credential_id, crate::webauthn::MAX_CREDENTIAL_ID_LEN)
        && decodes(&model.public_key, 2048)
        && (0..=i64::from(u32::MAX)).contains(&model.sign_count)
        && model.transports.as_deref().is_none_or(|value| {
            value.len() <= 256 && serde_json::from_str::<Vec<String>>(value).is_ok()
        })
        && (model.backup_eligible || !model.backup_state)
        && validate_name(&model.name).is_ok_and(|name| name == model.name)
        && model.created_at >= 0
        && model
            .last_used_at
            .is_none_or(|last_used_at| last_used_at >= model.created_at)
}

fn validate_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(AppError::Validation(format!(
            "a passkey name must have 1 to {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(name.to_owned())
}
