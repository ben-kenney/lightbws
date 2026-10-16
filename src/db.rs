pub mod entities;
mod migration;
mod organization_key;

use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use sea_orm::{
    ConnectOptions, Database as SeaDatabase, DatabaseConnection,
    sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous},
};
use sea_orm_migration::MigratorTrait;

use self::migration::Migrator;
pub use self::organization_key::KeyMigrationReport;
use crate::sdk_crypto::OrganizationKey;

#[derive(Clone)]
pub struct Database {
    connection: DatabaseConnection,
    organization_key: OrganizationKey,
}

impl Database {
    /// Opens the database and binds it to its organization key. A database that was never bound
    /// to a key has its legacy SDK ciphertext re-encrypted under `organization_key` first; a
    /// database bound to a different key is refused.
    pub async fn connect(path: &Path, organization_key: OrganizationKey) -> Result<Self> {
        Ok(Self::connect_with_report(path, organization_key).await?.0)
    }

    pub async fn connect_with_report(
        path: &Path,
        organization_key: OrganizationKey,
    ) -> Result<(Self, Option<KeyMigrationReport>)> {
        let connection = open(path).await?;
        let report = organization_key::bind(&connection, &organization_key).await?;
        Ok((
            Self {
                connection,
                organization_key,
            },
            report,
        ))
    }

    /// Whether the database at `path` has already been bound to an organization key.
    pub async fn has_organization_key(path: &Path) -> Result<bool> {
        let connection = open(path).await?;
        let bound = organization_key::is_bound(&connection).await?;
        connection.close().await?;
        Ok(bound)
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }

    pub fn organization_key(&self) -> &OrganizationKey {
        &self.organization_key
    }
}

async fn open(path: &Path) -> Result<DatabaseConnection> {
    let database_url = format!("sqlite://{}?mode=rwc", path.display());
    let mut options = ConnectOptions::new(database_url);
    options
        .max_connections(5)
        .min_connections(1)
        .connect_timeout(std::time::Duration::from_secs(10))
        .acquire_timeout(std::time::Duration::from_secs(10))
        .sqlx_logging(false);
    options.map_sqlx_sqlite_opts(|options| {
        options
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
    });
    let connection = SeaDatabase::connect(options)
        .await
        .with_context(|| format!("failed to open SQLite database at {}", path.display()))?;
    Migrator::up(&connection, None)
        .await
        .context("failed to migrate SQLite database")?;
    Ok(connection)
}
