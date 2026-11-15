//! Time-based one-time passwords (RFC 6238) with the parameters every common authenticator
//! app supports: HMAC-SHA-1, 6 digits and a 30-second step.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Length of a generated secret in bytes (the HMAC-SHA-1 block output size).
pub const SECRET_LEN: usize = 20;
pub const DIGITS: usize = 6;
pub const STEP_SECONDS: i64 = 30;
/// Steps accepted either side of the current one, to tolerate clock drift.
pub const WINDOW: i64 = 1;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The time step that `timestamp` (Unix seconds) falls in.
pub fn step_at(timestamp: i64) -> i64 {
    timestamp.div_euclid(STEP_SECONDS)
}

/// The code for one time step, zero-padded to [`DIGITS`] digits.
pub fn code_at(secret: &[u8], step: i64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&u64::try_from(step).unwrap_or(0).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:0DIGITS$}", binary % 10_u32.pow(DIGITS as u32))
}

/// Returns the time step whose code equals `code`, looking at the current step and [`WINDOW`]
/// steps either side. Steps at or before `last_used_step` are skipped so that a code cannot be
/// replayed. Every candidate is compared in constant time.
pub fn matching_step(
    secret: &[u8],
    code: &str,
    timestamp: i64,
    last_used_step: Option<i64>,
) -> Option<i64> {
    let code = normalize_code(code)?;
    let current = step_at(timestamp);
    let mut matched = None;
    for step in (current - WINDOW)..=(current + WINDOW) {
        let equal = code_at(secret, step).as_bytes().ct_eq(code.as_bytes());
        if bool::from(equal) && last_used_step.is_none_or(|last| step > last) && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

/// Strips the spaces authenticator apps show between digit groups.
fn normalize_code(code: &str) -> Option<String> {
    let code = code
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    (code.len() == DIGITS && code.bytes().all(|byte| byte.is_ascii_digit())).then_some(code)
}

/// RFC 4648 Base32 without padding, the form authenticator apps accept for manual entry.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(
                BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize],
            ));
        }
    }
    if bits > 0 {
        output.push(char::from(
            BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
}

/// Decodes unpadded or padded RFC 4648 Base32, ignoring case, spaces and hyphens.
pub fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for character in value.chars() {
        if character.is_whitespace() || matches!(character, '-' | '=') {
            continue;
        }
        let upper = character.to_ascii_uppercase();
        let index = BASE32_ALPHABET
            .iter()
            .position(|candidate| char::from(*candidate) == upper)?;
        buffer = (buffer << 5) | index as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(output)
}

/// The `otpauth://` URI that authenticator apps read from a QR code.
pub fn provisioning_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let mut uri = url::Url::parse("otpauth://totp/").expect("static URI");
    uri.set_path(&format!("{issuer}:{account}"));
    uri.query_pairs_mut()
        .append_pair("secret", &base32_encode(secret))
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", &DIGITS.to_string())
        .append_pair("period", &STEP_SECONDS.to_string());
    uri.into()
}

#[cfg(test)]
mod tests {
    use super::{base32_decode, base32_encode, code_at, matching_step, provisioning_uri, step_at};

    /// The shared secret of the RFC 6238 appendix B test vectors for SHA-1.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn reproduces_the_rfc_6238_sha1_vectors() {
        // The RFC lists 8-digit codes; a 6-digit code is their last six digits.
        for (timestamp, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(code_at(RFC_SECRET, step_at(timestamp)), expected[2..]);
        }
    }

    #[test]
    fn accepts_one_step_either_side_and_nothing_further() {
        let now = 1_234_567_890;
        let current = step_at(now);
        for (offset, accepted) in [(-2, false), (-1, true), (0, true), (1, true), (2, false)] {
            let code = code_at(RFC_SECRET, current + offset);
            assert_eq!(
                matching_step(RFC_SECRET, &code, now, None),
                accepted.then_some(current + offset),
                "offset {offset}"
            );
        }
        assert_eq!(matching_step(RFC_SECRET, "000000", now, None), None);
        assert_eq!(matching_step(RFC_SECRET, "12345", now, None), None);
        assert_eq!(matching_step(RFC_SECRET, "12345a", now, None), None);
    }

    #[test]
    fn rejects_a_replayed_or_older_step() {
        let now = 1_234_567_890;
        let current = step_at(now);
        let code = code_at(RFC_SECRET, current);
        assert_eq!(
            matching_step(RFC_SECRET, &code, now, Some(current - 1)),
            Some(current)
        );
        assert_eq!(matching_step(RFC_SECRET, &code, now, Some(current)), None);
        let earlier = code_at(RFC_SECRET, current - 1);
        assert_eq!(
            matching_step(RFC_SECRET, &earlier, now, Some(current)),
            None
        );
    }

    #[test]
    fn tolerates_the_spacing_authenticator_apps_display() {
        let now = 59;
        assert_eq!(
            matching_step(RFC_SECRET, " 287 082 ", now, None),
            Some(step_at(now))
        );
    }

    #[test]
    fn base32_round_trips_and_matches_rfc_4648() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(
            base32_encode(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(base32_decode("mzxw 6ytb-oi==").unwrap(), b"foobar");
        assert_eq!(
            base32_decode(&base32_encode(RFC_SECRET)).unwrap(),
            RFC_SECRET
        );
        assert!(base32_decode("not base32!").is_none());
    }

    #[test]
    fn provisioning_uri_escapes_the_account_name() {
        let uri = provisioning_uri("LightBWS", "ops team@example", RFC_SECRET);
        assert!(uri.starts_with("otpauth://totp/LightBWS:ops%20team@example?secret=GEZDGNBV"));
        assert!(uri.contains("&issuer=LightBWS&algorithm=SHA1&digits=6&period=30"));
    }
}
