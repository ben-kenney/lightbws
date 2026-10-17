use anyhow::{Context, Result, bail};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend,
    DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter, Statement, TransactionTrait,
};

use super::entities::{machine_access_token, machine_session, project, secret};
use crate::{
    domain::{ORGANIZATION_ID, now},
    sdk_crypto::{OrganizationKey, legacy},
};

const KEY_CHECK_PLAINTEXT: &str = "lightbws-organization-key-check-v1";

/// What binding a database to its organization key changed. Counts are per ciphertext column
/// value (`name_cipher`, `key_cipher`, `value_cipher`, `note_cipher`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyMigrationReport {
    /// Values that decrypted under the published legacy key before the migration.
    pub legacy_before: u64,
    /// Values re-encrypted under the instance key.
    pub reencrypted: u64,
    /// Values that still decrypt under the published legacy key afterwards. Always zero.
    pub legacy_after: u64,
    /// Values that decrypt under neither key (for example opaque client ciphertext); left as-is.
    pub unreadable: u64,
    /// Access tokens revoked because they could only unwrap the published legacy key.
    pub revoked_access_tokens: u64,
}

pub(super) async fn is_bound(connection: &DatabaseConnection) -> Result<bool> {
    Ok(key_check(connection).await?.is_some())
}

pub(super) async fn bind(
    connection: &DatabaseConnection,
    key: &OrganizationKey,
) -> Result<Option<KeyMigrationReport>> {
    if let Some(check) = key_check(connection).await? {
        if key.decrypt(&check).ok().as_deref() != Some(KEY_CHECK_PLAINTEXT) {
            bail!(
                "the organization key does not match this database; restore the keyfile this \
                 database was created with"
            );
        }
        return Ok(None);
    }

    let transaction = connection.begin().await?;
    let mut report = KeyMigrationReport {
        legacy_before: count_legacy(&transaction).await?,
        ..KeyMigrationReport::default()
    };
    for model in project::Entity::find()
        .filter(project::Column::NameCipher.is_not_null())
        .all(&transaction)
        .await?
    {
        let name = reencrypt(model.name_cipher.as_deref(), key, &mut report)?;
        if name != model.name_cipher {
            let mut active = model.into_active_model();
            active.name_cipher = Set(name);
            active.update(&transaction).await?;
        }
    }
    for model in secret::Entity::find()
        .filter(secret::Column::KeyCipher.is_not_null())
        .all(&transaction)
        .await?
    {
        let key_cipher = reencrypt(model.key_cipher.as_deref(), key, &mut report)?;
        let value_cipher = reencrypt(model.value_cipher.as_deref(), key, &mut report)?;
        let note_cipher = reencrypt(model.note_cipher.as_deref(), key, &mut report)?;
        if key_cipher != model.key_cipher
            || value_cipher != model.value_cipher
            || note_cipher != model.note_cipher
        {
            let mut active = model.into_active_model();
            active.key_cipher = Set(key_cipher);
            active.value_cipher = Set(value_cipher);
            active.note_cipher = Set(note_cipher);
            active.update(&transaction).await?;
        }
    }

    // Tokens minted before per-token wrapping carry the published key in their second half, so
    // they can never be given the new organization key.
    let legacy_tokens = machine_access_token::Entity::find()
        .filter(machine_access_token::Column::EncryptedPayload.is_null())
        .filter(machine_access_token::Column::RevokedAt.is_null())
        .all(&transaction)
        .await?;
    let timestamp = now();
    for token in legacy_tokens {
        machine_session::Entity::delete_many()
            .filter(machine_session::Column::MachineAccessTokenId.eq(token.id.clone()))
            .exec(&transaction)
            .await?;
        let revoked_at = timestamp.max(token.created_at);
        let mut active = token.into_active_model();
        active.revoked_at = Set(Some(revoked_at));
        active.update(&transaction).await?;
        report.revoked_access_tokens += 1;
    }

    report.legacy_after = count_legacy(&transaction).await?;
    if report.legacy_after != 0 {
        transaction.rollback().await?;
        bail!(
            "{} values still decrypt under the published legacy key after migration",
            report.legacy_after
        );
    }
    let check = key
        .encrypt(KEY_CHECK_PLAINTEXT)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let updated = transaction
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE organizations SET key_check = ? WHERE id = ? AND key_check IS NULL",
            [check.into(), ORGANIZATION_ID.into()],
        ))
        .await?;
    if updated.rows_affected() != 1 {
        transaction.rollback().await?;
        bail!("failed to record the organization key check");
    }
    transaction
        .commit()
        .await
        .context("failed to commit organization key migration")?;
    tracing::info!(
        legacy_before = report.legacy_before,
        reencrypted = report.reencrypted,
        legacy_after = report.legacy_after,
        unreadable = report.unreadable,
        revoked_access_tokens = report.revoked_access_tokens,
        "bound database to its organization key"
    );
    Ok(Some(report))
}

async fn key_check(connection: &impl ConnectionTrait) -> Result<Option<String>> {
    let row = connection
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT key_check FROM organizations WHERE id = ?",
            [ORGANIZATION_ID.into()],
        ))
        .await?
        .context("organization record is missing")?;
    Ok(row.try_get::<Option<String>>("", "key_check")?)
}

fn reencrypt(
    value: Option<&str>,
    key: &OrganizationKey,
    report: &mut KeyMigrationReport,
) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match legacy::decrypt(value) {
        Ok(plaintext) => {
            report.reencrypted += 1;
            Ok(Some(
                key.encrypt(&plaintext)
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
            ))
        }
        Err(_) => {
            if key.decrypt(value).is_err() {
                report.unreadable += 1;
            }
            Ok(Some(value.to_owned()))
        }
    }
}

async fn count_legacy(connection: &impl ConnectionTrait) -> Result<u64> {
    let mut count = 0;
    for model in project::Entity::find()
        .filter(project::Column::NameCipher.is_not_null())
        .all(connection)
        .await?
    {
        count += u64::from(is_legacy(model.name_cipher.as_deref()));
    }
    for model in secret::Entity::find()
        .filter(secret::Column::KeyCipher.is_not_null())
        .all(connection)
        .await?
    {
        count += u64::from(is_legacy(model.key_cipher.as_deref()))
            + u64::from(is_legacy(model.value_cipher.as_deref()))
            + u64::from(is_legacy(model.note_cipher.as_deref()));
    }
    Ok(count)
}

fn is_legacy(value: Option<&str>) -> bool {
    value.is_some_and(|value| legacy::decrypt(value).is_ok())
}
