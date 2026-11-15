use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use axum::http::HeaderName;
use secrecy::SecretString;

use crate::domain::{
    secret_history::{DEFAULT_HISTORY_LIMIT, MAX_HISTORY_LIMIT},
    two_factor::TwoFactorPolicy,
};
use crate::webauthn::RelyingParty;

#[derive(Clone)]
pub struct BootstrapAdmin {
    pub username: String,
    pub password: SecretString,
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub bootstrap_admin: Option<BootstrapAdmin>,
    pub cookie_secure: bool,
    pub allow_plaintext_backups: bool,
    pub master_key: Option<SecretString>,
    pub organization_key_file: Option<PathBuf>,
    /// Request header that carries the client address set by a trusted reverse proxy.
    pub ip_header: Option<HeaderName>,
    /// Optional file that receives a plain-text copy of the log, for tools such as fail2ban.
    pub log_file: Option<PathBuf>,
    /// Earlier versions kept per secret. Zero stops recording history.
    pub secret_history_limit: u32,
    /// Who must set up a second factor before using the web client.
    pub require_2fa: TwoFactorPolicy,
    /// Username whose second factor is removed once at start-up, for an administrator who lost
    /// both the authenticator and the recovery codes.
    pub reset_2fa_for: Option<String>,
    /// The address users open in their browser. Passkeys are bound to it; unset disables them.
    pub public_url: Option<RelyingParty>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind = env_value("LIGHTBWS_BIND")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .context("LIGHTBWS_BIND is invalid")?;
        let data_dir =
            PathBuf::from(env_value("LIGHTBWS_DATA_DIR").unwrap_or_else(|| "data".into()));
        let username = env_value("LIGHTBWS_ADMIN_USERNAME");
        let password = env_value("LIGHTBWS_ADMIN_PASSWORD");
        let bootstrap_admin = match (username, password) {
            (Some(username), Some(password)) => Some(BootstrapAdmin {
                username: validate_username(&username)?.to_owned(),
                password: SecretString::from(validate_password(&password)?.to_owned()),
            }),
            (None, None) => None,
            _ => bail!("LIGHTBWS_ADMIN_USERNAME and LIGHTBWS_ADMIN_PASSWORD must be set together"),
        };
        let cookie_secure = parse_bool("LIGHTBWS_COOKIE_SECURE", false)?;
        if parse_bool("LIGHTBWS_ENABLE_UPSTREAM_COMPATIBILITY_ACCOUNT", false)? {
            bail!(
                "LIGHTBWS_ENABLE_UPSTREAM_COMPATIBILITY_ACCOUNT has been removed: its fixed public \
                 credentials could only work by exposing the organization key"
            );
        }
        let allow_plaintext_backups = parse_bool("LIGHTBWS_ALLOW_PLAINTEXT_BACKUPS", false)?;
        let master_key = env_value("LIGHTBWS_MASTER_KEY").map(SecretString::from);
        let organization_key_file = env_value("LIGHTBWS_ORGANIZATION_KEY_FILE").map(PathBuf::from);
        let ip_header = env_value("LIGHTBWS_IP_HEADER")
            .map(|name| parse_ip_header(&name))
            .transpose()?;
        let log_file = env_value("LIGHTBWS_LOG_FILE").map(PathBuf::from);
        let secret_history_limit = env_value("LIGHTBWS_SECRET_HISTORY_LIMIT")
            .map(|value| parse_history_limit(&value))
            .transpose()?
            .unwrap_or(DEFAULT_HISTORY_LIMIT);
        let require_2fa = match env_value("LIGHTBWS_REQUIRE_2FA") {
            Some(value) => TwoFactorPolicy::parse(&value)
                .context("LIGHTBWS_REQUIRE_2FA must be off, admins or all")?,
            None => TwoFactorPolicy::Off,
        };
        let reset_2fa_for = env_value("LIGHTBWS_RESET_2FA_FOR");
        let public_url = env_value("LIGHTBWS_PUBLIC_URL")
            .map(|value| {
                RelyingParty::from_public_url(&value)
                    .map_err(|reason| anyhow::anyhow!("invalid LIGHTBWS_PUBLIC_URL: {reason}"))
            })
            .transpose()?;
        Ok(Self {
            bind,
            data_dir,
            bootstrap_admin,
            cookie_secure,
            allow_plaintext_backups,
            master_key,
            organization_key_file,
            ip_header,
            log_file,
            secret_history_limit,
            require_2fa,
            reset_2fa_for,
            public_url,
        })
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("lightbws.sqlite3")
    }

    pub fn master_key_path(&self) -> PathBuf {
        self.data_dir.join("master.key")
    }

    /// The organization keyfile. It must live outside the data directory so that a copy of the
    /// data directory, a snapshot or a backup of it is not enough to decrypt stored secrets.
    pub fn organization_key_path(&self) -> Result<PathBuf> {
        let Some(path) = &self.organization_key_file else {
            bail!(
                "LIGHTBWS_ORGANIZATION_KEY_FILE must name the organization keyfile, outside \
                 LIGHTBWS_DATA_DIR (for example /etc/lightbws/organization.key)"
            );
        };
        let data_dir = resolve(&self.data_dir).context("failed to resolve LIGHTBWS_DATA_DIR")?;
        let key_path = std::path::absolute(path).context("failed to resolve the keyfile path")?;
        // Resolving the keyfile itself also catches a symlink that points into the data directory.
        let resolved_key = resolve(&key_path).context("failed to resolve the keyfile path")?;
        if resolved_key.starts_with(&data_dir) {
            bail!("LIGHTBWS_ORGANIZATION_KEY_FILE must be outside LIGHTBWS_DATA_DIR");
        }
        Ok(key_path)
    }
}

/// Canonicalizes the nearest existing ancestor of `path` and re-appends the missing components, so
/// that paths whose directories do not exist yet compare in the same form as existing ones.
fn resolve(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(resolved) => {
                return Ok(missing
                    .into_iter()
                    .rev()
                    .fold(resolved, |path, part| path.join(part)));
            }
            Err(_) => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Ok(absolute);
                };
                missing.push(name.to_owned());
                existing = parent;
            }
        }
    }
}

pub fn validate_username(value: &str) -> Result<&str> {
    let value = value.trim();
    if !(1..=128).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        bail!("username must contain 1-128 non-control characters");
    }
    Ok(value)
}

pub fn validate_password(value: &str) -> Result<&str> {
    if !(6..=4096).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        bail!("password must contain 6-4096 non-control characters");
    }
    Ok(value)
}

pub fn parse_ip_header(value: &str) -> Result<HeaderName> {
    HeaderName::try_from(value.trim()).context("LIGHTBWS_IP_HEADER is not a valid header name")
}

pub fn parse_history_limit(value: &str) -> Result<u32> {
    value
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|limit| *limit <= MAX_HISTORY_LIMIT)
        .with_context(|| {
            format!("LIGHTBWS_SECRET_HISTORY_LIMIT must be a number from 0 to {MAX_HISTORY_LIMIT}")
        })
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_bool(name: &str, default: bool) -> Result<bool> {
    match env_value(name).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => bail!("{name} must be true or false"),
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("bind", &self.bind)
            .field("data_dir", &self.data_dir)
            .field("bootstrap_admin", &self.bootstrap_admin.is_some())
            .field("cookie_secure", &self.cookie_secure)
            .field("allow_plaintext_backups", &self.allow_plaintext_backups)
            .field(
                "master_key",
                &self.master_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("organization_key_file", &self.organization_key_file)
            .field("ip_header", &self.ip_header)
            .field("log_file", &self.log_file)
            .field("secret_history_limit", &self.secret_history_limit)
            .field("require_2fa", &self.require_2fa)
            .field("reset_2fa_for", &self.reset_2fa_for)
            .field("public_url", &self.public_url)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Config, parse_history_limit, parse_ip_header, validate_password, validate_username,
    };

    #[test]
    fn parses_the_secret_history_limit() {
        assert_eq!(parse_history_limit(" 0 ").unwrap(), 0);
        assert_eq!(parse_history_limit("1000").unwrap(), 1000);
        assert!(parse_history_limit("1001").is_err());
        assert!(parse_history_limit("-1").is_err());
        assert!(parse_history_limit("many").is_err());
    }

    #[test]
    fn validates_bootstrap_credentials() {
        assert_eq!(validate_username(" admin ").unwrap(), "admin");
        assert!(validate_username("").is_err());
        assert!(validate_username("bad\nname").is_err());
        assert!(validate_password("123456").is_ok());
        assert!(validate_password("12345").is_err());
    }

    #[test]
    fn parses_the_client_ip_header() {
        assert_eq!(
            parse_ip_header(" X-Real-IP ").unwrap().as_str(),
            "x-real-ip"
        );
        assert!(parse_ip_header("not a header").is_err());
    }

    #[test]
    fn organization_keyfile_must_be_outside_the_data_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let config = |key: Option<std::path::PathBuf>| Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data_dir.clone(),
            bootstrap_admin: None,
            cookie_secure: false,
            allow_plaintext_backups: false,
            master_key: None,
            organization_key_file: key,
            ip_header: None,
            log_file: None,
            secret_history_limit: 20,
            require_2fa: Default::default(),
            reset_2fa_for: None,
            public_url: None,
        };
        assert!(config(None).organization_key_path().is_err());
        assert!(
            config(Some(data_dir.join("organization.key")))
                .organization_key_path()
                .is_err()
        );
        assert!(
            config(Some(data_dir.join("nested").join("organization.key")))
                .organization_key_path()
                .is_err()
        );
        assert!(
            config(Some(root.path().join("keys").join("organization.key")))
                .organization_key_path()
                .is_ok()
        );
        // A data directory that does not exist yet still compares correctly.
        let missing_data = root.path().join("not-yet").join("data");
        let mut missing = config(Some(missing_data.join("keys").join("organization.key")));
        missing.data_dir = missing_data.clone();
        assert!(missing.organization_key_path().is_err());
        // A keyfile symlinked into the data directory is rejected.
        #[cfg(unix)]
        {
            let target = data_dir.join("organization.key");
            std::fs::write(&target, "key").unwrap();
            let link_dir = root.path().join("etc");
            std::fs::create_dir_all(&link_dir).unwrap();
            let link = link_dir.join("organization.key");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(config(Some(link)).organization_key_path().is_err());
        }
    }
}
