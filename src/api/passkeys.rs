//! Passkey routes: managing the signed-in user's passkeys, and the two ways to sign in with
//! one (as the step after a password, or on its own). Every route answers 404 when the
//! instance has no `LIGHTBWS_PUBLIC_URL`.
//!
//! The WebAuthn challenge is the token of a `login_challenges` row, so the challenge a browser
//! signs is looked up by its digest and is tied to one ceremony kind and, where known, one user.

use std::net::{IpAddr, SocketAddr};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::two_factor::{confirm_password, record};
use crate::{
    AppState,
    auth::{
        PendingMutationSession, PendingSession, revoke_other_sessions, second_factor_rate_key,
        session_response,
    },
    client_ip::{self, FailureReason, LoginKind},
    db::entities::{login_challenge, user},
    domain::{
        audit::{AuditActor, AuditRepository},
        passkeys::{
            CredentialDescriptor, LOGIN_CHALLENGE, PasskeyRepository, PublicPasskey,
            REGISTER_CHALLENGE,
        },
        two_factor::{CHALLENGE_TTL_SECONDS, SECOND_FACTOR_CHALLENGE},
        users::UserRepository,
    },
    error::AppError,
    webauthn::{self, RelyingParty},
};

const RELYING_PARTY_NAME: &str = "LightBWS";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameInput {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    challenge: String,
}

/// The parts of a browser `PublicKeyCredential` the server reads, binary fields in Base64url.
/// Fields it does not need (`rawId`, `type`, extension results) are ignored.
#[derive(Deserialize)]
struct AttestationInput {
    id: String,
    response: AttestationResponse,
}

#[derive(Deserialize)]
struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Deserialize)]
struct AssertionInput {
    id: String,
    response: AssertionResponse,
}

#[derive(Deserialize)]
struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(default, rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterInput {
    name: String,
    credential: AttestationInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInInput {
    credential: AssertionInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Registered {
    passkey: PublicPasskey,
    /// Present when this passkey is the account's first second factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list))
        .route("/register/options", post(register_options))
        .route("/register/verify", post(register_verify))
        .route("/{id}", put(rename).delete(remove))
}

pub fn login_routes() -> Router<AppState> {
    Router::new()
        .route("/login/passkey/options", post(second_step_options))
        .route("/login/passkey/verify", post(second_step_verify))
        .route("/passkey/options", post(sign_in_options))
        .route("/passkey/verify", post(sign_in_verify))
}

fn relying_party(state: &AppState) -> Result<&RelyingParty, AppError> {
    state.passkeys.as_ref().ok_or(AppError::NotFound)
}

async fn list(
    State(state): State<AppState>,
    PendingSession(session): PendingSession,
) -> Result<Json<Vec<PublicPasskey>>, AppError> {
    relying_party(&state)?;
    Ok(Json(
        PasskeyRepository::new(state.db.clone())
            .list(session.user_id)
            .await?,
    ))
}

async fn register_options(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Json(input): Json<PasswordInput>,
) -> Result<Json<Value>, AppError> {
    let relying_party = relying_party(&state)?;
    confirm_password(&state, &session, input.password).await?;
    let existing = PasskeyRepository::new(state.db.clone())
        .descriptors(session.user_id)
        .await?;
    let challenge = state
        .two_factor()
        .create_challenge(Some(session.user_id), REGISTER_CHALLENGE, None)
        .await?;
    Ok(Json(json!({
        "publicKey": {
            "rp": { "id": relying_party.id, "name": RELYING_PARTY_NAME },
            "user": {
                // A stable random handle; the username stays out of the authenticator's index.
                "id": URL_SAFE_NO_PAD.encode(session.user_id.as_bytes()),
                "name": session.user.username,
                "displayName": session.user.display_name,
            },
            "challenge": challenge,
            "pubKeyCredParams": webauthn::ALGORITHMS
                .iter()
                .map(|algorithm| json!({ "type": "public-key", "alg": algorithm }))
                .collect::<Vec<_>>(),
            "timeout": CHALLENGE_TTL_SECONDS * 1000,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "required",
                "requireResidentKey": true,
                "userVerification": "required",
            },
            "excludeCredentials": descriptors_json(&existing),
        }
    })))
}

async fn register_verify(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Json(input): Json<RegisterInput>,
) -> Result<(StatusCode, Json<Registered>), AppError> {
    let relying_party = relying_party(&state)?;
    let rejected = || AppError::Validation("the passkey could not be verified".into());
    let client_data = decode(&input.credential.response.client_data_json).ok_or_else(rejected)?;
    let attestation = decode(&input.credential.response.attestation_object).ok_or_else(rejected)?;
    let two_factor = state.two_factor();
    let token = webauthn::claimed_challenge(&client_data).ok_or_else(rejected)?;
    let challenge = two_factor
        .find_challenge(&token, REGISTER_CHALLENGE)
        .await?
        .filter(|challenge| challenge.user_id == Some(session.user_id.to_string()))
        .ok_or_else(|| AppError::Validation("the passkey setup expired; start it again".into()))?;
    // One attempt per challenge, whatever the outcome.
    if !two_factor.consume_challenge(&challenge.id).await? {
        return Err(rejected());
    }
    let registration =
        webauthn::verify_registration(relying_party, &token, &client_data, &attestation)
            .map_err(|_| rejected())?;
    if decode(&input.credential.id).as_deref() != Some(registration.credential_id.as_slice()) {
        return Err(rejected());
    }
    let (passkey, recovery_codes) = PasskeyRepository::new(state.db.clone())
        .register(
            session.user_id,
            &input.name,
            &registration,
            &input.credential.response.transports,
        )
        .await?;
    if recovery_codes.is_some() {
        // Anyone else holding a session for this account signed in without the new factor.
        revoke_other_sessions(&state, session.user_id, &session.session_digest).await?;
    }
    record(&state, session.user_id, "user.passkey.add").await?;
    Ok((
        StatusCode::CREATED,
        Json(Registered {
            passkey,
            recovery_codes,
        }),
    ))
}

async fn rename(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Path(id): Path<Uuid>,
    Json(input): Json<NameInput>,
) -> Result<Json<PublicPasskey>, AppError> {
    relying_party(&state)?;
    let passkey = PasskeyRepository::new(state.db.clone())
        .rename(session.user_id, id, &input.name)
        .await?;
    record(&state, session.user_id, "user.passkey.rename").await?;
    Ok(Json(passkey))
}

async fn remove(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Path(id): Path<Uuid>,
    Json(input): Json<PasswordInput>,
) -> Result<StatusCode, AppError> {
    relying_party(&state)?;
    confirm_password(&state, &session, input.password).await?;
    PasskeyRepository::new(state.db.clone())
        .remove(
            session.user_id,
            id,
            state.require_2fa.requires(session.user.role),
        )
        .await?;
    record(&state, session.user_id, "user.passkey.remove").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Request options for the step after a correct password, limited to that user's passkeys.
async fn second_step_options(
    State(state): State<AppState>,
    Json(input): Json<ChallengeInput>,
) -> Result<Json<Value>, AppError> {
    let relying_party = relying_party(&state)?;
    let challenge = state
        .two_factor()
        .find_challenge(&input.challenge, SECOND_FACTOR_CHALLENGE)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let user_id = challenge
        .user_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or(AppError::Unauthorized)?;
    let allowed = PasskeyRepository::new(state.db.clone())
        .descriptors(user_id)
        .await?;
    Ok(Json(request_options(
        relying_party,
        &input.challenge,
        &allowed,
    )))
}

async fn second_step_verify(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<SignInInput>,
) -> Result<Response, AppError> {
    sign_in(
        &state,
        peer,
        &headers,
        &input.credential,
        SECOND_FACTOR_CHALLENGE,
    )
    .await
}

/// Request options for signing in with a passkey alone: no user is named, so the authenticator
/// offers the credentials it holds for this site.
async fn sign_in_options(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let relying_party = relying_party(&state)?;
    let challenge = state
        .two_factor()
        .create_challenge(None, LOGIN_CHALLENGE, None)
        .await?;
    Ok(Json(request_options(relying_party, &challenge, &[])))
}

async fn sign_in_verify(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<SignInInput>,
) -> Result<Response, AppError> {
    sign_in(&state, peer, &headers, &input.credential, LOGIN_CHALLENGE).await
}

/// Why a passkey sign-in was refused, for the failed-login log.
struct Refusal {
    /// The account the attempt was for, when it got far enough to know.
    username: String,
}

async fn sign_in(
    state: &AppState,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
    credential: &AssertionInput,
    kind: &str,
) -> Result<Response, AppError> {
    let relying_party = relying_party(state)?;
    let client = client_ip::resolve(headers, peer.map(|peer| peer.0.0), state.ip_header.as_ref());
    let rate_key = second_factor_rate_key(client);
    if !state.second_factor_failures.check(&rate_key) {
        client_ip::log_login_failure(LoginKind::Web, client, FailureReason::RateLimited, "");
        return Err(AppError::RateLimited);
    }
    match verify_sign_in(state, relying_party, credential, kind, client).await? {
        Ok(model) => {
            let user = UserRepository::new(state.db.clone())
                .record_login(model)
                .await?;
            session_response(state, user).await
        }
        Err(refusal) => {
            state.second_factor_failures.record_failure(&rate_key);
            client_ip::log_login_failure(
                LoginKind::Web,
                client,
                FailureReason::InvalidPasskey,
                &refusal.username,
            );
            Err(AppError::Unauthorized)
        }
    }
}

async fn verify_sign_in(
    state: &AppState,
    relying_party: &RelyingParty,
    credential: &AssertionInput,
    kind: &str,
    client: Option<IpAddr>,
) -> Result<Result<user::Model, Refusal>, AppError> {
    let unknown = || Refusal {
        username: String::new(),
    };
    let (Some(client_data), Some(authenticator_data), Some(signature)) = (
        decode(&credential.response.client_data_json),
        decode(&credential.response.authenticator_data),
        decode(&credential.response.signature),
    ) else {
        return Ok(Err(unknown()));
    };
    let two_factor = state.two_factor();
    let Some(token) = webauthn::claimed_challenge(&client_data) else {
        return Ok(Err(unknown()));
    };
    let Some(challenge) = two_factor.find_challenge(&token, kind).await? else {
        return Ok(Err(unknown()));
    };
    let second_step = kind == SECOND_FACTOR_CHALLENGE;
    if !second_step && !two_factor.consume_challenge(&challenge.id).await? {
        // A passkey-only challenge is good for one attempt.
        return Ok(Err(unknown()));
    }
    let outcome = check_assertion(
        state,
        relying_party,
        credential,
        &challenge,
        &token,
        (&client_data, &authenticator_data, &signature),
        client,
    )
    .await?;
    if second_step {
        // The password step allows a few wrong second steps of any kind before starting over.
        match &outcome {
            Ok(_) => {
                if !two_factor.consume_challenge(&challenge.id).await? {
                    return Ok(Err(unknown()));
                }
            }
            Err(_) => two_factor.fail_challenge(&challenge.id).await?,
        }
    }
    Ok(outcome)
}

async fn check_assertion(
    state: &AppState,
    relying_party: &RelyingParty,
    credential: &AssertionInput,
    challenge: &login_challenge::Model,
    token: &str,
    (client_data, authenticator_data, signature): (&[u8], &[u8], &[u8]),
    client: Option<IpAddr>,
) -> Result<Result<user::Model, Refusal>, AppError> {
    let users = UserRepository::new(state.db.clone());
    // After a password the account is known even when the passkey turns out to be wrong.
    let expected = match challenge.user_id.as_deref() {
        Some(user_id) => users.find_model(user_id).await?,
        None => None,
    };
    let refusal = |model: Option<&user::Model>| Refusal {
        username: model
            .or(expected.as_ref())
            .map(|model| model.username.clone())
            .unwrap_or_default(),
    };
    let passkeys = PasskeyRepository::new(state.db.clone());
    let Some(passkey) = passkeys.find_by_credential(&credential.id).await? else {
        return Ok(Err(refusal(None)));
    };
    if expected
        .as_ref()
        .is_some_and(|expected| expected.id != passkey.user_id)
        || (challenge.user_id.is_some() && expected.is_none())
    {
        return Ok(Err(refusal(None)));
    }
    let Some(model) = users.find_model(&passkey.user_id).await? else {
        return Ok(Err(refusal(None)));
    };
    let user_id = Uuid::parse_str(&model.id).map_err(AppError::internal)?;
    // Discoverable credentials name their user; it has to be the credential's owner.
    let handle_matches = match credential.response.user_handle.as_deref() {
        None | Some("") => true,
        Some(handle) => decode(handle).as_deref() == Some(user_id.as_bytes().as_slice()),
    };
    if model.disabled || !handle_matches {
        return Ok(Err(refusal(Some(&model))));
    }
    let Some(public_key) = decode(&passkey.public_key) else {
        return Ok(Err(refusal(Some(&model))));
    };
    let Ok(assertion) = webauthn::verify_assertion(
        relying_party,
        token,
        &public_key,
        client_data,
        authenticator_data,
        signature,
    ) else {
        return Ok(Err(refusal(Some(&model))));
    };
    if !passkeys.record_use(&passkey, &assertion).await? {
        // The signature is valid but the counter went backwards or repeated: the credential
        // may have been copied to a second authenticator.
        tracing::warn!(
            target: "lightbws::auth",
            ip = %client.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string()),
            username = ?model.username,
            "passkey signature counter did not advance"
        );
        AuditRepository::new(state.db.clone())
            .record(
                AuditActor::User(user_id),
                "user.passkey.counter_regression",
                "user",
                Some(user_id),
                "denied",
            )
            .await?;
        return Ok(Err(refusal(Some(&model))));
    }
    Ok(Ok(model))
}

fn request_options(
    relying_party: &RelyingParty,
    challenge: &str,
    allowed: &[CredentialDescriptor],
) -> Value {
    json!({
        "publicKey": {
            "challenge": challenge,
            "rpId": relying_party.id,
            "timeout": CHALLENGE_TTL_SECONDS * 1000,
            "userVerification": "required",
            "allowCredentials": descriptors_json(allowed),
        }
    })
}

fn descriptors_json(descriptors: &[CredentialDescriptor]) -> Vec<Value> {
    descriptors
        .iter()
        .map(|descriptor| {
            json!({
                "type": "public-key",
                "id": descriptor.id,
                "transports": descriptor.transports,
            })
        })
        .collect()
}

fn decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()
}
