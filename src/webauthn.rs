//! Relying-party side of WebAuthn, limited to what passkey sign-in needs: no attestation
//! (`attestation: "none"`), user verification always required, and ES256, EdDSA and RS256 keys.
//!
//! The functions here are pure: they check a browser's response against the configured origin
//! and an expected challenge. Storing credentials and making challenges single-use is the
//! caller's job (`domain::passkeys`).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use ring::signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;

/// COSE algorithm identifiers offered to authenticators, most preferred first.
pub const ALGORITHMS: [i64; 3] = [COSE_ES256, COSE_EDDSA, COSE_RS256];
const COSE_ES256: i64 = -7;
const COSE_EDDSA: i64 = -8;
const COSE_RS256: i64 = -257;

/// The longest credential ID the specification allows.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
const MAX_PUBLIC_KEY_LEN: usize = 2048;

/// The site passkeys are bound to, derived from `LIGHTBWS_PUBLIC_URL`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    /// Exactly what the browser reports as the page origin, such as `https://secrets.example.com`.
    pub origin: String,
    /// The host name credentials are scoped to.
    pub id: String,
}

impl RelyingParty {
    /// Browsers only offer WebAuthn in a secure context, so the URL must be HTTPS, or HTTP on
    /// `localhost` for development.
    pub fn from_public_url(value: &str) -> Result<Self, String> {
        let url = Url::parse(value.trim()).map_err(|error| error.to_string())?;
        let host = url.host_str().ok_or("the URL has no host")?;
        match url.scheme() {
            "https" => {}
            "http" if host == "localhost" => {}
            _ => return Err("the URL must use https, or http on localhost".into()),
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err("the URL must not contain a path, query or fragment".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("the URL must not contain credentials".into());
        }
        if matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))) {
            return Err("the URL must use a host name, not an IP address".into());
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            id: host.to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The response is not well-formed.
    Malformed,
    /// The response is for another ceremony type.
    Ceremony,
    Challenge,
    Origin,
    RelyingParty,
    UserNotPresent,
    UserNotVerified,
    UnsupportedKey,
    Signature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// A new credential, checked and ready to store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    /// The credential public key as the authenticator sent it (a COSE key).
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    /// The credential may be synced between devices.
    pub backup_eligible: bool,
    /// The credential is currently synced.
    pub backup_state: bool,
}

/// A checked sign-in assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

/// The challenge a response claims to answer, so the caller can look it up. Nothing about the
/// response is trusted until `verify_registration` or `verify_assertion` succeeds.
pub fn claimed_challenge(client_data_json: &[u8]) -> Option<String> {
    serde_json::from_slice::<ClientData>(client_data_json)
        .ok()
        .map(|data| data.challenge)
}

pub fn verify_registration(
    relying_party: &RelyingParty,
    challenge: &str,
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<Registration, Error> {
    check_client_data(
        relying_party,
        client_data_json,
        "webauthn.create",
        challenge,
    )?;
    let attestation: Value =
        ciborium::de::from_reader(attestation_object).map_err(|_| Error::Malformed)?;
    let authenticator_data = map_get_text(&attestation, "authData")
        .and_then(Value::as_bytes)
        .ok_or(Error::Malformed)?;
    let data = parse_authenticator_data(relying_party, authenticator_data)?;
    if data.flags & FLAG_ATTESTED_CREDENTIAL == 0 {
        return Err(Error::Malformed);
    }
    // aaguid (16) || credential ID length (2) || credential ID || COSE public key || extensions
    let rest = data.rest;
    if rest.len() < 18 {
        return Err(Error::Malformed);
    }
    let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
    if id_len == 0 || id_len > MAX_CREDENTIAL_ID_LEN || rest.len() < 18 + id_len {
        return Err(Error::Malformed);
    }
    let credential_id = rest[18..18 + id_len].to_vec();
    let key_and_extensions = &rest[18 + id_len..];
    let mut reader = key_and_extensions;
    let key: Value = ciborium::de::from_reader(&mut reader).map_err(|_| Error::Malformed)?;
    let public_key = &key_and_extensions[..key_and_extensions.len() - reader.len()];
    if public_key.len() > MAX_PUBLIC_KEY_LEN {
        return Err(Error::UnsupportedKey);
    }
    PublicKey::from_cose(&key)?;
    Ok(Registration {
        credential_id,
        public_key: public_key.to_vec(),
        sign_count: data.sign_count,
        backup_eligible: data.flags & FLAG_BACKUP_ELIGIBLE != 0,
        backup_state: data.flags & FLAG_BACKUP_STATE != 0,
    })
}

pub fn verify_assertion(
    relying_party: &RelyingParty,
    challenge: &str,
    public_key: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<Assertion, Error> {
    check_client_data(relying_party, client_data_json, "webauthn.get", challenge)?;
    let data = parse_authenticator_data(relying_party, authenticator_data)?;
    let key: Value = ciborium::de::from_reader(public_key).map_err(|_| Error::UnsupportedKey)?;
    let key = PublicKey::from_cose(&key)?;
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&signed, signature)?;
    Ok(Assertion {
        sign_count: data.sign_count,
        backup_eligible: data.flags & FLAG_BACKUP_ELIGIBLE != 0,
        backup_state: data.flags & FLAG_BACKUP_STATE != 0,
    })
}

fn check_client_data(
    relying_party: &RelyingParty,
    client_data_json: &[u8],
    ceremony: &str,
    challenge: &str,
) -> Result<(), Error> {
    let data: ClientData =
        serde_json::from_slice(client_data_json).map_err(|_| Error::Malformed)?;
    if data.kind != ceremony {
        return Err(Error::Ceremony);
    }
    // Compare the decoded bytes, so padding or alphabet differences cannot matter.
    let decode = |value: &str| URL_SAFE_NO_PAD.decode(value.trim_end_matches('='));
    match (decode(&data.challenge), decode(challenge)) {
        (Ok(received), Ok(expected)) if !expected.is_empty() && received == expected => {}
        _ => return Err(Error::Challenge),
    }
    if data.origin != relying_party.origin || data.cross_origin {
        return Err(Error::Origin);
    }
    Ok(())
}

struct AuthenticatorData<'a> {
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn parse_authenticator_data<'a>(
    relying_party: &RelyingParty,
    bytes: &'a [u8],
) -> Result<AuthenticatorData<'a>, Error> {
    if bytes.len() < 37 {
        return Err(Error::Malformed);
    }
    if bytes[..32] != Sha256::digest(relying_party.id.as_bytes())[..] {
        return Err(Error::RelyingParty);
    }
    let flags = bytes[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(Error::UserNotPresent);
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(Error::UserNotVerified);
    }
    Ok(AuthenticatorData {
        flags,
        sign_count: u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]),
        rest: &bytes[37..],
    })
}

enum PublicKey {
    /// Uncompressed P-256 point.
    Es256(Vec<u8>),
    Ed25519(Vec<u8>),
    Rs256 {
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

impl PublicKey {
    fn from_cose(key: &Value) -> Result<Self, Error> {
        let integer = |label: i64| map_get_int(key, label).and_then(as_i64);
        let bytes = |label: i64| map_get_int(key, label).and_then(Value::as_bytes);
        let unsupported = Error::UnsupportedKey;
        match (integer(1), integer(3)) {
            // EC2 key on P-256.
            (Some(2), Some(COSE_ES256)) => {
                let (x, y) = (bytes(-2).ok_or(unsupported)?, bytes(-3).ok_or(unsupported)?);
                if integer(-1) != Some(1) || x.len() != 32 || y.len() != 32 {
                    return Err(unsupported);
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                Ok(Self::Es256(point))
            }
            // Octet key pair on Ed25519.
            (Some(1), Some(COSE_EDDSA)) => {
                let x = bytes(-2).ok_or(unsupported)?;
                if integer(-1) != Some(6) || x.len() != 32 {
                    return Err(unsupported);
                }
                Ok(Self::Ed25519(x.clone()))
            }
            (Some(3), Some(COSE_RS256)) => {
                let (n, e) = (bytes(-1).ok_or(unsupported)?, bytes(-2).ok_or(unsupported)?);
                if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 8 {
                    return Err(unsupported);
                }
                Ok(Self::Rs256 {
                    n: n.clone(),
                    e: e.clone(),
                })
            }
            _ => Err(unsupported),
        }
    }

    fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Es256(point) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                    .verify(message, signature_bytes)
            }
            Self::Ed25519(key) => signature::UnparsedPublicKey::new(&signature::ED25519, key)
                .verify(message, signature_bytes),
            Self::Rs256 { n, e } => signature::RsaPublicKeyComponents { n, e }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                signature_bytes,
            ),
        }
        .map_err(|_| Error::Signature)
    }
}

fn as_i64(value: &Value) -> Option<i64> {
    value
        .as_integer()
        .and_then(|integer| i64::try_from(integer).ok())
}

fn map_get_int(map: &Value, label: i64) -> Option<&Value> {
    map.as_map()?
        .iter()
        .find(|(key, _)| as_i64(key) == Some(label))
        .map(|(_, value)| value)
}

fn map_get_text<'a>(map: &'a Value, label: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(key, _)| key.as_text() == Some(label))
        .map(|(_, value)| value)
}

/// A software authenticator for tests: it produces the same bytes a platform authenticator
/// would for an ES256 credential.
#[doc(hidden)]
pub mod testing {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ciborium::Value;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use sha2::{Digest, Sha256};

    pub struct SoftwareAuthenticator {
        key: EcdsaKeyPair,
        pub credential_id: Vec<u8>,
        pub sign_count: u32,
        /// Flags sent with every response. Defaults to user present and verified.
        pub flags: u8,
        /// Whether to sign correctly. Turn off to produce a bad signature.
        pub honest: bool,
        /// Whether the signature counter advances. Synced passkeys always report zero.
        pub counts: bool,
    }

    pub struct AttestationResponse {
        pub client_data_json: Vec<u8>,
        pub attestation_object: Vec<u8>,
    }

    pub struct AssertionResponse {
        pub client_data_json: Vec<u8>,
        pub authenticator_data: Vec<u8>,
        pub signature: Vec<u8>,
    }

    impl SoftwareAuthenticator {
        pub fn new(credential_id: &[u8]) -> Self {
            let random = SystemRandom::new();
            let document =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
            Self {
                key: EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    document.as_ref(),
                    &random,
                )
                .unwrap(),
                credential_id: credential_id.to_vec(),
                sign_count: 0,
                flags: super::FLAG_USER_PRESENT | super::FLAG_USER_VERIFIED,
                honest: true,
                counts: true,
            }
        }

        pub fn cose_key(&self) -> Vec<u8> {
            let point = self.key.public_key().as_ref();
            let key = Value::Map(vec![
                (Value::from(1), Value::from(2)),
                (Value::from(3), Value::from(-7)),
                (Value::from(-1), Value::from(1)),
                (Value::from(-2), Value::Bytes(point[1..33].to_vec())),
                (Value::from(-3), Value::Bytes(point[33..65].to_vec())),
            ]);
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&key, &mut bytes).unwrap();
            bytes
        }

        fn authenticator_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            data.push(
                self.flags
                    | if attested {
                        super::FLAG_ATTESTED_CREDENTIAL
                    } else {
                        0
                    },
            );
            data.extend_from_slice(&self.sign_count.to_be_bytes());
            if attested {
                data.extend_from_slice(&[0; 16]);
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_key());
            }
            data
        }

        pub fn create(&self, rp_id: &str, origin: &str, challenge: &str) -> AttestationResponse {
            let attestation = Value::Map(vec![
                (Value::from("fmt"), Value::from("none")),
                (Value::from("attStmt"), Value::Map(Vec::new())),
                (
                    Value::from("authData"),
                    Value::Bytes(self.authenticator_data(rp_id, true)),
                ),
            ]);
            let mut attestation_object = Vec::new();
            ciborium::ser::into_writer(&attestation, &mut attestation_object).unwrap();
            AttestationResponse {
                client_data_json: client_data("webauthn.create", origin, challenge),
                attestation_object,
            }
        }

        pub fn get(&mut self, rp_id: &str, origin: &str, challenge: &str) -> AssertionResponse {
            if self.counts {
                self.sign_count += 1;
            }
            let client_data_json = client_data("webauthn.get", origin, challenge);
            let authenticator_data = self.authenticator_data(rp_id, false);
            let mut signed = authenticator_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data_json));
            if !self.honest {
                signed.push(0);
            }
            let signature = self
                .key
                .sign(&SystemRandom::new(), &signed)
                .unwrap()
                .as_ref()
                .to_vec();
            AssertionResponse {
                client_data_json,
                authenticator_data,
                signature,
            }
        }
    }

    pub fn client_data(kind: &str, origin: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Error, FLAG_USER_PRESENT, RelyingParty, claimed_challenge,
        testing::{SoftwareAuthenticator, encode},
        verify_assertion, verify_registration,
    };

    fn relying_party() -> RelyingParty {
        RelyingParty::from_public_url("https://secrets.example.com").unwrap()
    }

    #[test]
    fn public_url_gives_the_origin_and_relying_party_id() {
        let party = RelyingParty::from_public_url(" https://Secrets.Example.com:8443/ ").unwrap();
        assert_eq!(party.origin, "https://secrets.example.com:8443");
        assert_eq!(party.id, "secrets.example.com");
        let default_port =
            RelyingParty::from_public_url("https://secrets.example.com:443").unwrap();
        assert_eq!(default_port.origin, "https://secrets.example.com");
        let local = RelyingParty::from_public_url("http://localhost:8080").unwrap();
        assert_eq!(local.origin, "http://localhost:8080");
        assert_eq!(local.id, "localhost");
        for invalid in [
            "http://secrets.example.com",
            "https://secrets.example.com/app",
            "https://secrets.example.com/?a=1",
            "https://user@secrets.example.com",
            "https://192.0.2.1",
            "ftp://secrets.example.com",
            "secrets.example.com",
        ] {
            assert!(RelyingParty::from_public_url(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn registration_and_assertion_round_trip() {
        let party = relying_party();
        let mut authenticator = SoftwareAuthenticator::new(b"credential-1");
        let challenge = encode(&[7; 32]);
        let created = authenticator.create(&party.id, &party.origin, &challenge);
        assert_eq!(
            claimed_challenge(&created.client_data_json).as_deref(),
            Some(challenge.as_str())
        );
        let registration = verify_registration(
            &party,
            &challenge,
            &created.client_data_json,
            &created.attestation_object,
        )
        .unwrap();
        assert_eq!(registration.credential_id, b"credential-1");
        assert_eq!(registration.public_key, authenticator.cose_key());
        assert!(!registration.backup_eligible);

        let challenge = encode(&[9; 32]);
        let response = authenticator.get(&party.id, &party.origin, &challenge);
        let assertion = verify_assertion(
            &party,
            &challenge,
            &registration.public_key,
            &response.client_data_json,
            &response.authenticator_data,
            &response.signature,
        )
        .unwrap();
        assert_eq!(assertion.sign_count, 1);
    }

    #[test]
    fn assertions_are_bound_to_challenge_origin_site_and_key() {
        let party = relying_party();
        let mut authenticator = SoftwareAuthenticator::new(b"credential-1");
        let key = authenticator.cose_key();
        let challenge = encode(&[1; 32]);
        let check = |response: &super::testing::AssertionResponse, challenge: &str, key: &[u8]| {
            verify_assertion(
                &party,
                challenge,
                key,
                &response.client_data_json,
                &response.authenticator_data,
                &response.signature,
            )
        };

        let good = authenticator.get(&party.id, &party.origin, &challenge);
        assert!(check(&good, &challenge, &key).is_ok());
        assert_eq!(check(&good, &encode(&[2; 32]), &key), Err(Error::Challenge));
        assert_eq!(check(&good, "", &key), Err(Error::Challenge));

        let phished = authenticator.get(&party.id, "https://secrets.example.net", &challenge);
        assert_eq!(check(&phished, &challenge, &key), Err(Error::Origin));

        let other_site = authenticator.get("example.net", &party.origin, &challenge);
        assert_eq!(
            check(&other_site, &challenge, &key),
            Err(Error::RelyingParty)
        );

        let other_key = SoftwareAuthenticator::new(b"credential-2").cose_key();
        assert_eq!(check(&good, &challenge, &other_key), Err(Error::Signature));

        let mut tampered = authenticator.get(&party.id, &party.origin, &challenge);
        tampered.authenticator_data[36] ^= 1;
        assert_eq!(check(&tampered, &challenge, &key), Err(Error::Signature));

        authenticator.flags = FLAG_USER_PRESENT;
        let unverified = authenticator.get(&party.id, &party.origin, &challenge);
        assert_eq!(
            check(&unverified, &challenge, &key),
            Err(Error::UserNotVerified)
        );

        // A registration response cannot be replayed as a sign-in.
        let created = authenticator.create(&party.id, &party.origin, &challenge);
        assert_eq!(
            verify_assertion(
                &party,
                &challenge,
                &key,
                &created.client_data_json,
                &good.authenticator_data,
                &good.signature
            ),
            Err(Error::Ceremony)
        );
    }

    #[test]
    fn malformed_registrations_are_rejected_without_panicking() {
        let party = relying_party();
        let authenticator = SoftwareAuthenticator::new(b"credential-1");
        let challenge = encode(&[3; 32]);
        let created = authenticator.create(&party.id, &party.origin, &challenge);
        for length in 0..created.attestation_object.len() {
            assert!(
                verify_registration(
                    &party,
                    &challenge,
                    &created.client_data_json,
                    &created.attestation_object[..length],
                )
                .is_err()
            );
        }
        assert_eq!(
            verify_registration(&party, &challenge, b"{}", &created.attestation_object),
            Err(Error::Malformed)
        );
    }
}
