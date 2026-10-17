use anyhow::{Context, Result};
use lightbws::{
    AppState, config::Config, create_app, crypto::MasterKey, db::Database,
    domain::users::UserRepository, sdk_crypto::OrganizationKey,
};
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lightbws=info,tower_http=info".into()),
        )
        .init();
    let config = Config::from_env()?;
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .with_context(|| format!("failed to create {}", config.data_dir.display()))?;
    let organization_key = load_or_create_organization_key(&config).await?;
    let db = Database::connect(&config.database_path(), organization_key).await?;
    let users = UserRepository::new(db.clone());
    users.bootstrap(config.bootstrap_admin.as_ref()).await?;
    let master_key = MasterKey::load_or_create(&config)?;
    let state = AppState::new(db, &config).with_master_key(master_key);
    lightbws::domain::backups::recover_interrupted_jobs(&state.db).await?;
    tokio::spawn(lightbws::domain::backups::scheduler(state.clone()));
    tokio::spawn(lightbws::domain::audit::scheduler(state.db.clone()));
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "LightBWS is listening");
    axum::serve(
        listener,
        create_app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

async fn load_or_create_organization_key(config: &Config) -> Result<OrganizationKey> {
    let path = config.organization_key_path()?;
    if path.exists() {
        return OrganizationKey::load(&path);
    }
    if Database::has_organization_key(&config.database_path()).await? {
        anyhow::bail!(
            "organization keyfile {} is missing, but this database was encrypted with one; \
             restore the keyfile (secrets cannot be decrypted without it)",
            path.display()
        );
    }
    let key = OrganizationKey::random()?;
    key.write_new(&path)?;
    tracing::warn!(
        path = %path.display(),
        "generated a new organization key; back up this file separately, losing it loses every \
         stored secret"
    );
    Ok(key)
}

async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
