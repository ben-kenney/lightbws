//! Bitwarden-compatible organization key handling.
//!
//! Every installation owns a random organization key that is loaded from a keyfile kept outside
//! the data directory. SDK clients receive the key only wrapped under a random per-token key that
//! exists solely in the access token handed to the operator, so neither the database nor the
//! repository is enough to decrypt stored ciphertext.

use std::{fs::OpenOptions, io::Write, path::Path, sync::Arc};

use aes::Aes256;
use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

const KEY_LEN: usize = 64;
const ACCESS_KEY_LEN: usize = 16;

#[derive(Clone)]
pub struct OrganizationKey(Arc<[u8; KEY_LEN]>);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationPayload {
    encryption_key: String,
}

/// The per-token half of an SDK access token and the organization key wrapped under it.
pub(crate) struct WrappedOrganizationKey {
    pub access_key: String,
    pub encrypted_payload: String,
}

impl OrganizationKey {
    /// Generates a new random AES-256-CBC + HMAC-SHA256 organization key.
    pub fn random() -> anyhow::Result<Self> {
        let mut bytes = [0_u8; KEY_LEN];
        rand::rng()
            .try_fill_bytes(&mut bytes)
            .context("failed to obtain random bytes")?;
        Ok(Self(Arc::new(bytes)))
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let decoded = STANDARD
            .decode(value.trim())
            .context("organization key must be Base64")?;
        let bytes: [u8; KEY_LEN] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("organization key must contain exactly 64 bytes"))?;
        Ok(Self(Arc::new(bytes)))
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("failed to inspect {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    "organization keyfile is readable by other users; restrict it to mode 0600"
                );
            }
        }
        let value = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&value)
            .with_context(|| format!("invalid organization key in {}", path.display()))
    }

    /// Writes the key to a new owner-only file. Refuses to overwrite an existing file.
    pub fn write_new(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        writeln!(file, "{}", STANDARD.encode(self.0.as_ref()))
            .with_context(|| format!("failed to write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", path.display()))?;
        Ok(())
    }

    pub fn encrypt(&self, value: &str) -> Result<String, AppError> {
        encrypt_with_key(value, &self.0)
    }

    pub fn decrypt(&self, value: &str) -> Result<String, AppError> {
        decrypt_with_key(value, &self.0)
    }

    /// Wraps the organization key under a fresh random access key. The caller stores only the
    /// payload and hands the access key to the operator inside the access token.
    pub(crate) fn wrap_for_access_token(&self) -> Result<WrappedOrganizationKey, AppError> {
        let mut access_key = [0_u8; ACCESS_KEY_LEN];
        rand::rng()
            .try_fill_bytes(&mut access_key)
            .map_err(AppError::internal)?;
        let payload = serde_json::to_string(&OrganizationPayload {
            encryption_key: STANDARD.encode(self.0.as_ref()),
        })
        .map_err(AppError::internal)?;
        let encrypted_payload = encrypt_with_key(&payload, &derive_access_key(&access_key)?)?;
        Ok(WrappedOrganizationKey {
            access_key: STANDARD.encode(access_key),
            encrypted_payload,
        })
    }

    /// A non-secret identifier that tells whether two installations share the same key.
    pub fn fingerprint(&self) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.0[32..]).expect("HMAC key length");
        mac.update(b"lightbws-organization-key-fingerprint");
        hex::encode(&mac.finalize().into_bytes()[..16])
    }

    pub(crate) fn to_base64(&self) -> String {
        STANDARD.encode(self.0.as_ref())
    }
}

impl std::fmt::Debug for OrganizationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OrganizationKey([REDACTED])")
    }
}

/// Unwraps an organization key payload with the per-token access key, as an SDK client does.
pub fn unwrap_access_token_payload(
    access_key: &str,
    encrypted_payload: &str,
) -> Result<OrganizationKey, AppError> {
    let access_key: [u8; ACCESS_KEY_LEN] = STANDARD
        .decode(access_key)
        .map_err(|_| AppError::Validation("invalid access key".into()))?
        .try_into()
        .map_err(|_| AppError::Validation("invalid access key".into()))?;
    let payload = decrypt_with_key(encrypted_payload, &derive_access_key(&access_key)?)?;
    let payload: OrganizationPayload =
        serde_json::from_str(&payload).map_err(AppError::internal)?;
    OrganizationKey::parse(&payload.encryption_key).map_err(AppError::internal)
}

/// The organization key every LightBWS release before per-instance keys derived from constants
/// published in the repository. It is used only to find, re-encrypt and verify legacy rows and
/// legacy archives; it never encrypts new data or reaches an SDK client.
pub mod legacy {
    use std::sync::LazyLock;

    use super::{OrganizationKey, unwrap_access_token_payload};
    use crate::error::AppError;

    const PUBLISHED_ACCESS_KEY: &str = "X8vbvA0bduihIDe/qrzIQQ==";
    const PUBLISHED_PAYLOAD: &str = concat!(
        "2.E9fE8+M/VWMfhhim1KlCbQ==|eLsHR484S/tJbIkM6spnG/HP65tj9A6Tba7kAAvUp+rYuQmGLixiOCfMsqt5OvBctDfvvr/Aes",
        "Bu7cZimPLyOEhqEAjn52jF0eaI38XZfeOG2VJl0LOf60Wkfh3ryAMvfvLj3G4ZCNYU8sNgoC2+IQ==|lNApuCQ4Pyakfo/wwuuajWNaEX/2MW8/3rjXB/V7n+k="
    );

    static KEY: LazyLock<OrganizationKey> = LazyLock::new(|| {
        unwrap_access_token_payload(PUBLISHED_ACCESS_KEY, PUBLISHED_PAYLOAD)
            .expect("published legacy organization key payload must be valid")
    });

    /// Decrypts ciphertext written under the published legacy key.
    pub fn decrypt(value: &str) -> Result<String, AppError> {
        KEY.decrypt(value)
    }
}

fn derive_access_key(secret: &[u8; 16]) -> Result<[u8; 64], AppError> {
    let mut extract = <HmacSha256 as Mac>::new_from_slice(b"bitwarden-accesstoken")
        .map_err(AppError::internal)?;
    extract.update(secret);
    let prk = extract.finalize().into_bytes();
    let info = b"sm-access-token";

    let mut first = <HmacSha256 as Mac>::new_from_slice(&prk).map_err(AppError::internal)?;
    first.update(info);
    first.update(&[1]);
    let first = first.finalize().into_bytes();

    let mut second = <HmacSha256 as Mac>::new_from_slice(&prk).map_err(AppError::internal)?;
    second.update(&first);
    second.update(info);
    second.update(&[2]);
    let second = second.finalize().into_bytes();

    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(&first);
    key[32..].copy_from_slice(&second);
    Ok(key)
}

fn encrypt_with_key(value: &str, key: &[u8; 64]) -> Result<String, AppError> {
    let mut iv = [0_u8; 16];
    rand::rng()
        .try_fill_bytes(&mut iv)
        .map_err(AppError::internal)?;
    let ciphertext = Encryptor::<Aes256>::new_from_slices(&key[..32], &iv)
        .map_err(AppError::internal)?
        .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes());
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&key[32..]).map_err(AppError::internal)?;
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();
    Ok(format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(ciphertext),
        STANDARD.encode(mac)
    ))
}

fn decrypt_with_key(value: &str, key: &[u8; 64]) -> Result<String, AppError> {
    let Some(value) = value.strip_prefix("2.") else {
        return Err(AppError::Validation("unsupported SDK ciphertext".into()));
    };
    let mut parts = value.split('|');
    let (Some(iv), Some(ciphertext), Some(mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AppError::Validation("invalid SDK ciphertext".into()));
    };
    let iv = STANDARD.decode(iv).map_err(AppError::internal)?;
    let ciphertext = STANDARD.decode(ciphertext).map_err(AppError::internal)?;
    let mac = STANDARD.decode(mac).map_err(AppError::internal)?;
    if iv.len() != 16 || mac.len() != 32 {
        return Err(AppError::Validation("invalid SDK ciphertext".into()));
    }
    let mut expected =
        <HmacSha256 as Mac>::new_from_slice(&key[32..]).map_err(AppError::internal)?;
    expected.update(&iv);
    expected.update(&ciphertext);
    if expected
        .finalize()
        .into_bytes()
        .as_slice()
        .ct_eq(&mac)
        .unwrap_u8()
        != 1
    {
        return Err(AppError::Validation("invalid SDK ciphertext".into()));
    }
    let plaintext = Decryptor::<Aes256>::new_from_slices(&key[..32], &iv)
        .map_err(AppError::internal)?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|_| AppError::Validation("invalid SDK ciphertext".into()))?;
    String::from_utf8(plaintext).map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::{OrganizationKey, legacy, unwrap_access_token_payload};

    #[test]
    fn sdk_cipher_round_trip_uses_bitwarden_enc_string_format() {
        let key = OrganizationKey::random().expect("key");
        let encrypted = key.encrypt("Web SDK project").expect("encrypt");
        assert!(encrypted.starts_with("2."));
        assert_eq!(key.decrypt(&encrypted).expect("decrypt"), "Web SDK project");
    }

    #[test]
    fn independent_keys_cannot_read_each_other() {
        let first = OrganizationKey::random().expect("key");
        let second = OrganizationKey::random().expect("key");
        let encrypted = first.encrypt("secret").expect("encrypt");
        assert!(second.decrypt(&encrypted).is_err());
        assert!(legacy::decrypt(&encrypted).is_err());
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn access_token_wrapping_uses_a_fresh_sixteen_byte_key() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let key = OrganizationKey::random().expect("key");
        let first = key.wrap_for_access_token().expect("wrap");
        let second = key.wrap_for_access_token().expect("wrap");
        assert_eq!(
            STANDARD.decode(&first.access_key).expect("base64").len(),
            16
        );
        assert_ne!(first.access_key, second.access_key);
        let unwrapped = unwrap_access_token_payload(&first.access_key, &first.encrypted_payload)
            .expect("unwrap");
        assert_eq!(unwrapped.to_base64(), key.to_base64());
        assert!(unwrap_access_token_payload(&second.access_key, &first.encrypted_payload).is_err());
    }

    #[test]
    fn keyfile_round_trip_is_owner_only_and_never_overwritten() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("keys").join("organization.key");
        let key = OrganizationKey::random().expect("key");
        key.write_new(&path).expect("write");
        assert!(OrganizationKey::random().unwrap().write_new(&path).is_err());
        assert_eq!(
            OrganizationKey::load(&path).unwrap().to_base64(),
            key.to_base64()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn legacy_key_still_decrypts_official_bitwarden_sdk_fixture() {
        let fixture = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        assert_eq!(legacy::decrypt(fixture).expect("official fixture"), "TEST");
    }
}
