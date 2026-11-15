//! Second factors for web sign-in: TOTP secrets, single-use recovery codes and the short-lived
//! challenge that links the password step to the second step.
//!
//! Nothing here is specific to TOTP beyond the functions named for it: the challenge table
//! carries a kind and an opaque state, and recovery codes and the enforcement policy apply to
//! any confirmed second factor.

use rand::TryRng;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait,
    PaginatorTrait, QueryFilter, Statement, TransactionTrait,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::MasterKey,
    db::{
        Database,
        entities::{login_challenge, user_passkey, user_recovery_code, user_totp},
    },
    domain::{now, passkeys, users::Role},
    error::AppError,
    totp,
};

/// How long a sign-in challenge stays valid after the password step.
pub const CHALLENGE_TTL_SECONDS: i64 = 5 * 60;
/// Wrong codes accepted per challenge before it is discarded.
pub const MAX_CHALLENGE_FAILURES: i64 = 5;
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Challenge kind for the step after a correct password.
pub const SECOND_FACTOR_CHALLENGE: &str = "second_factor";
const ISSUER: &str = "LightBWS";
/// Random bytes per recovery code (80 bits).
const RECOVERY_CODE_BYTES: usize = 10;

/// Who must have a second factor before using the web client (`LIGHTBWS_REQUIRE_2FA`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TwoFactorPolicy {
    #[default]
    Off,
    Admins,
    All,
}

impl TwoFactorPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "admins" => Some(Self::Admins),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub fn requires(self, role: Role) -> bool {
        match self {
            Self::Off => false,
            Self::Admins => role == Role::Admin,
            Self::All => true,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorStatus {
    /// Whether the user has any confirmed second factor.
    pub enabled: bool,
    pub totp_enabled: bool,
    pub passkey_count: u64,
    pub recovery_codes_remaining: u64,
    /// Whether policy requires this user to have a second factor.
    pub required: bool,
}

/// Shown once while enrolling.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollment {
    pub secret: String,
    pub uri: String,
}

/// What a user presents as their second factor.
#[derive(Clone, Copy)]
pub enum SecondFactorProof<'a> {
    Totp(&'a str),
    RecoveryCode(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedFactor {
    Totp,
    RecoveryCode,
}

impl VerifiedFactor {
    /// The sign-in method name recorded for this factor.
    pub fn method(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::RecoveryCode => "recovery_code",
        }
    }
}

/// A confirmed TOTP secret in the clear, for archives only.
pub struct ExportedTotp {
    pub user_id: String,
    pub secret: String,
    pub confirmed_at: i64,
    pub last_used_step: Option<i64>,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct TwoFactorRepository {
    db: Database,
    master_key: MasterKey,
}

impl TwoFactorRepository {
    pub fn new(db: Database, master_key: MasterKey) -> Self {
        Self { db, master_key }
    }

    pub async fn status(&self, user_id: Uuid, required: bool) -> Result<TwoFactorStatus, AppError> {
        let totp_enabled = self.confirmed_totp(user_id).await?.is_some();
        let recovery_codes_remaining = user_recovery_code::Entity::find()
            .filter(user_recovery_code::Column::UserId.eq(user_id.to_string()))
            .filter(user_recovery_code::Column::UsedAt.is_null())
            .count(self.db.connection())
            .await?;
        let passkey_count = passkeys::count(self.db.connection(), &user_id.to_string()).await?;
        Ok(TwoFactorStatus {
            enabled: totp_enabled || passkey_count > 0,
            totp_enabled,
            passkey_count,
            recovery_codes_remaining,
            required,
        })
    }

    /// The sign-in methods a user can complete the second step with, besides a recovery code.
    /// `None` when the user has no confirmed second factor. The list can be empty: a user whose
    /// only factor is a passkey, on an instance where passkeys have since been turned off, can
    /// still only get in with a recovery code or an administrator's reset.
    pub async fn methods(
        &self,
        user_id: Uuid,
        passkeys_enabled: bool,
    ) -> Result<Option<Vec<&'static str>>, AppError> {
        let totp = self.confirmed_totp(user_id).await?.is_some();
        let passkey = passkeys::count(self.db.connection(), &user_id.to_string()).await? > 0;
        if !totp && !passkey {
            return Ok(None);
        }
        let mut methods = Vec::new();
        if totp {
            methods.push("totp");
        }
        if passkey && passkeys_enabled {
            methods.push("passkey");
        }
        Ok(Some(methods))
    }

    /// Starts TOTP enrolment: stores a fresh unconfirmed secret, replacing a pending one. A
    /// confirmed secret has to be removed first.
    pub async fn begin_totp(
        &self,
        user_id: Uuid,
        username: &str,
    ) -> Result<TotpEnrollment, AppError> {
        let transaction = self.db.connection().begin().await?;
        if let Some(existing) = user_totp::Entity::find_by_id(user_id.to_string())
            .one(&transaction)
            .await?
        {
            if existing.confirmed_at.is_some() {
                return Err(AppError::Conflict);
            }
            user_totp::Entity::delete_by_id(user_id.to_string())
                .exec(&transaction)
                .await?;
        }
        let mut secret = Zeroizing::new([0_u8; totp::SECRET_LEN]);
        rand::rng()
            .try_fill_bytes(secret.as_mut())
            .map_err(AppError::internal)?;
        user_totp::ActiveModel {
            user_id: Set(user_id.to_string()),
            secret_cipher: Set(self.encrypt_secret(user_id, secret.as_ref())?),
            confirmed_at: Set(None),
            last_used_step: Set(None),
            created_at: Set(now()),
        }
        .insert(&transaction)
        .await?;
        transaction.commit().await?;
        Ok(TotpEnrollment {
            secret: totp::base32_encode(secret.as_ref()),
            uri: totp::provisioning_uri(ISSUER, username, secret.as_ref()),
        })
    }

    /// Confirms a pending TOTP secret with a code generated from it. Returns a fresh set of
    /// recovery codes when this is the user's first second factor, `None` when the code is
    /// wrong or nothing is pending.
    pub async fn confirm_totp(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<Option<Vec<String>>, AppError> {
        let Some(pending) = user_totp::Entity::find_by_id(user_id.to_string())
            .one(self.db.connection())
            .await?
            .filter(|model| model.confirmed_at.is_none())
        else {
            return Ok(None);
        };
        let secret = self.decrypt_secret(user_id, &pending.secret_cipher)?;
        let timestamp = now();
        let Some(step) = totp::matching_step(&secret, code, timestamp, None) else {
            return Ok(None);
        };
        let transaction = self.db.connection().begin().await?;
        let confirmed = transaction
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE user_totp SET confirmed_at = ?, last_used_step = ? \
                 WHERE user_id = ? AND confirmed_at IS NULL",
                [
                    timestamp.max(pending.created_at).into(),
                    step.into(),
                    user_id.to_string().into(),
                ],
            ))
            .await?;
        if confirmed.rows_affected() != 1 {
            return Ok(None);
        }
        let codes = replace_recovery_codes(&transaction, user_id).await?;
        transaction.commit().await?;
        Ok(Some(codes))
    }

    /// Checks a second factor and consumes it: a TOTP time step cannot be used again and a
    /// recovery code works once.
    pub async fn verify(
        &self,
        user_id: Uuid,
        proof: SecondFactorProof<'_>,
    ) -> Result<Option<VerifiedFactor>, AppError> {
        match proof {
            SecondFactorProof::Totp(code) => Ok(self
                .verify_totp(user_id, code)
                .await?
                .then_some(VerifiedFactor::Totp)),
            SecondFactorProof::RecoveryCode(code) => Ok(self
                .use_recovery_code(user_id, code)
                .await?
                .then_some(VerifiedFactor::RecoveryCode)),
        }
    }

    async fn verify_totp(&self, user_id: Uuid, code: &str) -> Result<bool, AppError> {
        let Some(model) = self.confirmed_totp(user_id).await? else {
            return Ok(false);
        };
        let secret = self.decrypt_secret(user_id, &model.secret_cipher)?;
        let Some(step) = totp::matching_step(&secret, code, now(), model.last_used_step) else {
            return Ok(false);
        };
        // The guard makes the step single-use even when two requests race with the same code.
        let consumed = self
            .db
            .connection()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE user_totp SET last_used_step = ? WHERE user_id = ? \
                 AND confirmed_at IS NOT NULL AND (last_used_step IS NULL OR last_used_step < ?)",
                [step.into(), user_id.to_string().into(), step.into()],
            ))
            .await?;
        Ok(consumed.rows_affected() == 1)
    }

    async fn use_recovery_code(&self, user_id: Uuid, code: &str) -> Result<bool, AppError> {
        let Some(digest) = recovery_code_digest(code) else {
            return Ok(false);
        };
        let used = self
            .db
            .connection()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE user_recovery_codes SET used_at = MAX(?, created_at) \
                 WHERE user_id = ? AND code_digest = ? AND used_at IS NULL",
                [now().into(), user_id.to_string().into(), digest.into()],
            ))
            .await?;
        Ok(used.rows_affected() == 1)
    }

    /// Replaces the user's recovery codes; the previous set stops working.
    pub async fn regenerate_recovery_codes(&self, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let transaction = self.db.connection().begin().await?;
        let codes = replace_recovery_codes(&transaction, user_id).await?;
        transaction.commit().await?;
        Ok(codes)
    }

    /// Removes the user's TOTP secret, and the recovery codes with it when no other second
    /// factor remains. Returns whether a confirmed secret existed.
    pub async fn disable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        let transaction = self.db.connection().begin().await?;
        let existed = user_totp::Entity::find_by_id(user_id.to_string())
            .one(&transaction)
            .await?
            .is_some_and(|model| model.confirmed_at.is_some());
        user_totp::Entity::delete_by_id(user_id.to_string())
            .exec(&transaction)
            .await?;
        if passkeys::count(&transaction, &user_id.to_string()).await? == 0 {
            delete_recovery_codes(&transaction, user_id).await?;
        }
        transaction.commit().await?;
        Ok(existed)
    }

    /// Removes every second factor and recovery code of a user. Returns whether anything was
    /// removed.
    pub async fn reset(&self, user_id: Uuid) -> Result<bool, AppError> {
        let transaction = self.db.connection().begin().await?;
        let totp = user_totp::Entity::delete_by_id(user_id.to_string())
            .exec(&transaction)
            .await?
            .rows_affected;
        let codes = delete_recovery_codes(&transaction, user_id).await?;
        let removed_passkeys = user_passkey::Entity::delete_many()
            .filter(user_passkey::Column::UserId.eq(user_id.to_string()))
            .exec(&transaction)
            .await?
            .rows_affected;
        login_challenge::Entity::delete_many()
            .filter(login_challenge::Column::UserId.eq(user_id.to_string()))
            .exec(&transaction)
            .await?;
        transaction.commit().await?;
        Ok(totp + codes + removed_passkeys > 0)
    }

    /// Issues a single-use challenge and returns its token. Only a digest is stored.
    pub async fn create_challenge(
        &self,
        user_id: Option<Uuid>,
        kind: &str,
        state: Option<String>,
    ) -> Result<String, AppError> {
        let timestamp = now();
        login_challenge::Entity::delete_many()
            .filter(login_challenge::Column::ExpiresAt.lte(timestamp))
            .exec(self.db.connection())
            .await?;
        let token = crate::auth::random_token()?;
        login_challenge::ActiveModel {
            id: Set(crate::auth::digest(&token)),
            user_id: Set(user_id.map(|id| id.to_string())),
            kind: Set(kind.into()),
            state: Set(state),
            failed_attempts: Set(0),
            expires_at: Set(timestamp + CHALLENGE_TTL_SECONDS),
            created_at: Set(timestamp),
        }
        .insert(self.db.connection())
        .await?;
        Ok(token)
    }

    /// Looks up an unexpired challenge of the given kind by its token.
    pub async fn find_challenge(
        &self,
        token: &str,
        kind: &str,
    ) -> Result<Option<login_challenge::Model>, AppError> {
        let id = crate::auth::digest(token);
        let Some(model) = login_challenge::Entity::find_by_id(&id)
            .one(self.db.connection())
            .await?
        else {
            return Ok(None);
        };
        if model.expires_at <= now() {
            login_challenge::Entity::delete_by_id(&id)
                .exec(self.db.connection())
                .await?;
            return Ok(None);
        }
        Ok((model.kind == kind).then_some(model))
    }

    /// Counts a wrong attempt and discards the challenge once the limit is reached.
    pub async fn fail_challenge(&self, id: &str) -> Result<(), AppError> {
        self.db
            .connection()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE login_challenges SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                [id.into()],
            ))
            .await?;
        login_challenge::Entity::delete_many()
            .filter(login_challenge::Column::Id.eq(id))
            .filter(login_challenge::Column::FailedAttempts.gte(MAX_CHALLENGE_FAILURES))
            .exec(self.db.connection())
            .await?;
        Ok(())
    }

    /// Deletes a challenge. Returns `false` when it was already used, so it works only once.
    pub async fn consume_challenge(&self, id: &str) -> Result<bool, AppError> {
        Ok(login_challenge::Entity::delete_by_id(id)
            .exec(self.db.connection())
            .await?
            .rows_affected
            == 1)
    }

    /// Confirmed TOTP secrets decrypted for an archive. The archive is the only place a secret
    /// leaves the database in the clear, the same way backup target credentials do.
    pub(crate) async fn export_totp(
        &self,
        connection: &impl ConnectionTrait,
    ) -> Result<Vec<ExportedTotp>, AppError> {
        let mut exported = Vec::new();
        for model in user_totp::Entity::find()
            .filter(user_totp::Column::ConfirmedAt.is_not_null())
            .all(connection)
            .await?
        {
            let user_id = Uuid::parse_str(&model.user_id).map_err(AppError::internal)?;
            let secret = self.decrypt_secret(user_id, &model.secret_cipher)?;
            exported.push(ExportedTotp {
                secret: totp::base32_encode(&secret),
                confirmed_at: model.confirmed_at.unwrap_or(model.created_at),
                last_used_step: model.last_used_step,
                created_at: model.created_at,
                user_id: model.user_id,
            });
        }
        Ok(exported)
    }

    /// Encrypts an archived TOTP secret under this instance's master key.
    pub(crate) fn import_totp(
        &self,
        record: ExportedTotp,
    ) -> Result<user_totp::ActiveModel, AppError> {
        let invalid = || AppError::Validation("invalid two-factor record".into());
        let user_id = Uuid::parse_str(&record.user_id).map_err(|_| invalid())?;
        let secret = Zeroizing::new(totp::base32_decode(&record.secret).ok_or_else(invalid)?);
        if !(10..=64).contains(&secret.len())
            || record.created_at < 0
            || record.confirmed_at < record.created_at
            || record.last_used_step.is_some_and(|step| step < 0)
        {
            return Err(invalid());
        }
        Ok(user_totp::ActiveModel {
            user_id: Set(record.user_id),
            secret_cipher: Set(self.encrypt_secret(user_id, &secret)?),
            confirmed_at: Set(Some(record.confirmed_at)),
            last_used_step: Set(record.last_used_step),
            created_at: Set(record.created_at),
        })
    }

    async fn confirmed_totp(&self, user_id: Uuid) -> Result<Option<user_totp::Model>, AppError> {
        Ok(user_totp::Entity::find_by_id(user_id.to_string())
            .one(self.db.connection())
            .await?
            .filter(|model| model.confirmed_at.is_some()))
    }

    fn encrypt_secret(&self, user_id: Uuid, secret: &[u8]) -> Result<String, AppError> {
        self.master_key
            .encrypt(user_id.as_bytes(), secret)
            .map_err(AppError::internal)
    }

    fn decrypt_secret(&self, user_id: Uuid, cipher: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
        self.master_key
            .decrypt(user_id.as_bytes(), cipher)
            .map(Zeroizing::new)
            .map_err(AppError::internal)
    }
}

/// Break-glass for an administrator who lost both the authenticator and the recovery codes:
/// removes the named user's second factor, signs them out and records a system audit event.
/// Returns whether anything was removed.
pub async fn break_glass_reset(
    db: &Database,
    master_key: &MasterKey,
    username: &str,
) -> Result<bool, AppError> {
    use crate::db::entities::{session, user};

    let Some(model) = user::Entity::find()
        .filter(user::Column::Username.eq(username.trim()))
        .one(db.connection())
        .await?
    else {
        tracing::warn!(
            username = ?username,
            "LIGHTBWS_RESET_2FA_FOR names a user that does not exist"
        );
        return Ok(false);
    };
    let user_id = Uuid::parse_str(&model.id).map_err(AppError::internal)?;
    if !TwoFactorRepository::new(db.clone(), master_key.clone())
        .reset(user_id)
        .await?
    {
        return Ok(false);
    }
    session::Entity::delete_many()
        .filter(session::Column::UserId.eq(model.id.clone()))
        .exec(db.connection())
        .await?;
    crate::domain::audit::AuditRepository::new(db.clone())
        .record(
            crate::domain::audit::AuditActor::System,
            "user.2fa.reset",
            "user",
            Some(user_id),
            "changed",
        )
        .await?;
    tracing::warn!(
        username = ?model.username,
        "removed this user's second factor because LIGHTBWS_RESET_2FA_FOR is set; unset it now"
    );
    Ok(true)
}

/// Whether a user has a confirmed second factor.
pub async fn is_enabled(
    connection: &impl ConnectionTrait,
    user_id: &str,
) -> Result<bool, AppError> {
    Ok(user_totp::Entity::find_by_id(user_id)
        .one(connection)
        .await?
        .is_some_and(|model| model.confirmed_at.is_some())
        || passkeys::count(connection, user_id).await? > 0)
}

/// The users, out of all users, that have a confirmed second factor.
pub async fn enabled_user_ids(
    connection: &impl ConnectionTrait,
) -> Result<std::collections::HashSet<String>, AppError> {
    let mut users = user_totp::Entity::find()
        .filter(user_totp::Column::ConfirmedAt.is_not_null())
        .all(connection)
        .await?
        .into_iter()
        .map(|model| model.user_id)
        .collect::<std::collections::HashSet<_>>();
    users.extend(
        user_passkey::Entity::find()
            .all(connection)
            .await?
            .into_iter()
            .map(|model| model.user_id),
    );
    Ok(users)
}

pub(crate) async fn delete_recovery_codes(
    connection: &impl ConnectionTrait,
    user_id: Uuid,
) -> Result<u64, AppError> {
    Ok(user_recovery_code::Entity::delete_many()
        .filter(user_recovery_code::Column::UserId.eq(user_id.to_string()))
        .exec(connection)
        .await?
        .rows_affected)
}

pub(crate) async fn replace_recovery_codes(
    connection: &impl ConnectionTrait,
    user_id: Uuid,
) -> Result<Vec<String>, AppError> {
    delete_recovery_codes(connection, user_id).await?;
    let timestamp = now();
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = random_recovery_code()?;
        user_recovery_code::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            code_digest: Set(recovery_code_digest(&code).expect("generated code is well-formed")),
            used_at: Set(None),
            created_at: Set(timestamp),
        }
        .insert(connection)
        .await?;
        codes.push(code);
    }
    Ok(codes)
}

/// A code such as `ABCD-EFGH-IJKL-MNOP`: 80 random bits in Base32, grouped for reading.
fn random_recovery_code() -> Result<String, AppError> {
    let mut bytes = Zeroizing::new([0_u8; RECOVERY_CODE_BYTES]);
    rand::rng()
        .try_fill_bytes(bytes.as_mut())
        .map_err(AppError::internal)?;
    let encoded = totp::base32_encode(bytes.as_ref());
    Ok(encoded
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("Base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-"))
}

/// The stored form of a recovery code: SHA-256 of the code without grouping, in upper case.
/// Returns `None` for input that cannot be a recovery code.
fn recovery_code_digest(code: &str) -> Option<String> {
    let normalized = code
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    (normalized.len() == RECOVERY_CODE_BYTES * 8 / 5
        && normalized.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    .then(|| hex::encode(Sha256::digest(normalized.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::{TwoFactorPolicy, random_recovery_code, recovery_code_digest};
    use crate::domain::users::Role;

    #[test]
    fn policy_parses_and_applies_by_role() {
        assert_eq!(
            TwoFactorPolicy::parse(" Admins "),
            Some(TwoFactorPolicy::Admins)
        );
        assert_eq!(TwoFactorPolicy::parse("everyone"), None);
        assert!(!TwoFactorPolicy::Off.requires(Role::Admin));
        assert!(TwoFactorPolicy::Admins.requires(Role::Admin));
        assert!(!TwoFactorPolicy::Admins.requires(Role::User));
        assert!(TwoFactorPolicy::All.requires(Role::User));
    }

    #[test]
    fn recovery_codes_are_grouped_and_digested_without_grouping() {
        let code = random_recovery_code().unwrap();
        assert_eq!(code.len(), 19);
        assert_eq!(code.matches('-').count(), 3);
        let digest = recovery_code_digest(&code).unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(
            recovery_code_digest(&code.replace('-', " ").to_lowercase()).unwrap(),
            digest
        );
        assert_ne!(
            recovery_code_digest(&random_recovery_code().unwrap()).unwrap(),
            digest
        );
        assert!(recovery_code_digest("too-short").is_none());
        assert!(recovery_code_digest("").is_none());
    }
}
