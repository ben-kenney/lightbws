use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{ConnectInfo, Extension, FromRequestParts, State},
    http::{HeaderMap, HeaderValue, header, request::Parts},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::{Cookie, SameSite};
use rand::TryRng;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AppState,
    client_ip::{self, FailureReason, LoginKind},
    db::entities::session,
    domain::{
        audit::{AuditActor, AuditRepository},
        now,
        two_factor::{SECOND_FACTOR_CHALLENGE, SecondFactorProof, VerifiedFactor},
        users::{PublicUser, Role, UserRepository, verify_password},
    },
    error::AppError,
};

const SESSION_COOKIE: &str = "lightbws_session";
const CSRF_COOKIE: &str = "lightbws_csrf";
const SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;

#[derive(Clone)]
pub struct AuthenticatedSession {
    pub user_id: Uuid,
    pub csrf_digest: String,
    pub csrf_token: String,
    pub session_digest: String,
    pub user: PublicUser,
    /// Policy requires a second factor that this user has not set up yet.
    pub two_factor_enrollment_required: bool,
}

/// A session that may change state: it also carries a valid CSRF header.
pub struct MutationSession(pub AuthenticatedSession);

/// A signed-in session that may still owe a required second factor. Only the routes a user
/// needs to enrol, to see who they are and to sign out accept it; everything else takes
/// [`AuthenticatedSession`], which refuses such a session.
pub struct PendingSession(pub AuthenticatedSession);

/// [`PendingSession`] with a valid CSRF header.
pub struct PendingMutationSession(pub AuthenticatedSession);

#[derive(Deserialize)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecondFactorInput {
    pub challenge: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub user: PublicUser,
    pub csrf_token: String,
    /// Set when policy requires this user to add a second factor before doing anything else.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub two_factor_enrollment_required: bool,
}

/// The answer to a correct password when the account has a second factor: no session yet.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecondFactorChallenge {
    pub two_factor_required: bool,
    pub challenge: String,
    pub methods: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    pub initialized: bool,
    pub local_enabled: bool,
    /// Whether this instance is configured for passkeys (`LIGHTBWS_PUBLIC_URL`).
    pub passkeys_enabled: bool,
}

pub async fn config(State(state): State<AppState>) -> Result<Json<AuthConfig>, AppError> {
    use crate::db::entities::user;
    Ok(Json(AuthConfig {
        initialized: user::Entity::find()
            .one(state.db.connection())
            .await?
            .is_some(),
        local_enabled: true,
        passkeys_enabled: state.passkeys.is_some(),
    }))
}

pub async fn login(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    request_headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> Result<Response, AppError> {
    let client = client_ip::resolve(
        &request_headers,
        peer.map(|peer| peer.0.0),
        state.ip_header.as_ref(),
    );
    let refuse = |reason| {
        client_ip::log_login_failure(LoginKind::Web, client, reason, &input.username);
    };
    let rate_key = login_rate_key(&input.username, client);
    if let Err(error) = check_login_rate(&state, &rate_key).await {
        refuse(FailureReason::RateLimited);
        return Err(error);
    }
    let repository = UserRepository::new(state.db.clone());
    let model = match repository.find_login(&input.username).await {
        Ok(model) => model,
        Err(_) => {
            record_login_failure(&state, &rate_key).await;
            refuse(FailureReason::InvalidCredentials);
            return Err(AppError::Unauthorized);
        }
    };
    let hash = model.password_hash.clone();
    let password = input.password;
    let valid = tokio::task::spawn_blocking(move || verify_password(&hash, &password))
        .await
        .map_err(AppError::internal)?;
    if !valid || model.disabled {
        record_login_failure(&state, &rate_key).await;
        refuse(FailureReason::InvalidCredentials);
        return Err(AppError::Unauthorized);
    }
    clear_login_failures(&state, &rate_key).await;
    let user_id = Uuid::parse_str(&model.id).map_err(AppError::internal)?;
    let two_factor = state.two_factor();
    if let Some(methods) = two_factor
        .methods(user_id, state.passkeys.is_some())
        .await?
    {
        // The password is proven, but the session only exists after the second step.
        let challenge = two_factor
            .create_challenge(Some(user_id), SECOND_FACTOR_CHALLENGE, None)
            .await?;
        return Ok(Json(SecondFactorChallenge {
            two_factor_required: true,
            challenge,
            methods,
        })
        .into_response());
    }
    let user = repository.record_login(model).await?;
    session_response(&state, user).await
}

/// Completes a sign-in that the password step answered with a challenge.
pub async fn login_second_factor(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    request_headers: HeaderMap,
    Json(input): Json<SecondFactorInput>,
) -> Result<Response, AppError> {
    let client = client_ip::resolve(
        &request_headers,
        peer.map(|peer| peer.0.0),
        state.ip_header.as_ref(),
    );
    let rate_key = second_factor_rate_key(client);
    if !state.second_factor_failures.check(&rate_key) {
        client_ip::log_login_failure(LoginKind::Web, client, FailureReason::RateLimited, "");
        return Err(AppError::RateLimited);
    }
    let proof = match (input.code.as_deref(), input.recovery_code.as_deref()) {
        (Some(code), None) => SecondFactorProof::Totp(code),
        (None, Some(code)) => SecondFactorProof::RecoveryCode(code),
        _ => {
            return Err(AppError::Validation(
                "provide either a code or a recovery code".into(),
            ));
        }
    };
    let two_factor = state.two_factor();
    let Some(challenge) = two_factor
        .find_challenge(&input.challenge, SECOND_FACTOR_CHALLENGE)
        .await?
    else {
        state.second_factor_failures.record_failure(&rate_key);
        return Err(AppError::Unauthorized);
    };
    let repository = UserRepository::new(state.db.clone());
    let model = match challenge.user_id.as_deref() {
        Some(user_id) => repository.find_model(user_id).await?,
        None => None,
    };
    let Some(model) = model.filter(|model| !model.disabled) else {
        two_factor.consume_challenge(&challenge.id).await?;
        return Err(AppError::Unauthorized);
    };
    let user_id = Uuid::parse_str(&model.id).map_err(AppError::internal)?;
    let Some(factor) = two_factor.verify(user_id, proof).await? else {
        two_factor.fail_challenge(&challenge.id).await?;
        state.second_factor_failures.record_failure(&rate_key);
        client_ip::log_login_failure(
            LoginKind::Web,
            client,
            FailureReason::InvalidSecondFactor,
            &model.username,
        );
        return Err(AppError::Unauthorized);
    };
    if !two_factor.consume_challenge(&challenge.id).await? {
        return Err(AppError::Unauthorized);
    }
    if factor == VerifiedFactor::RecoveryCode {
        AuditRepository::new(state.db.clone())
            .record(
                AuditActor::User(user_id),
                "user.2fa.recovery_code.used",
                "user",
                Some(user_id),
                "allowed",
            )
            .await?;
    }
    let user = repository.record_login(model).await?;
    session_response(&state, user).await
}

/// Creates the session and its cookies. Every successful sign-in ends here.
pub(crate) async fn session_response(
    state: &AppState,
    user: PublicUser,
) -> Result<Response, AppError> {
    let (token, csrf_token) = create_session(state, user.id).await?;
    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.cookie_secure)
        .max_age(cookie::time::Duration::seconds(SESSION_TTL_SECONDS))
        .build();
    let mut response_headers = HeaderMap::new();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).map_err(AppError::internal)?,
    );
    let csrf_cookie = Cookie::build((CSRF_COOKIE, csrf_token.clone()))
        .path("/")
        .http_only(false)
        .same_site(SameSite::Strict)
        .secure(state.cookie_secure)
        .max_age(cookie::time::Duration::seconds(SESSION_TTL_SECONDS))
        .build();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie.to_string()).map_err(AppError::internal)?,
    );
    let two_factor_enrollment_required = enrollment_required(state, &user);
    Ok((
        response_headers,
        Json(SessionResponse {
            user,
            csrf_token,
            two_factor_enrollment_required,
        }),
    )
        .into_response())
}

pub async fn current(PendingSession(session): PendingSession) -> Json<SessionResponse> {
    Json(SessionResponse {
        user: session.user,
        csrf_token: session.csrf_token,
        two_factor_enrollment_required: session.two_factor_enrollment_required,
    })
}

pub async fn logout(
    State(state): State<AppState>,
    mutation: PendingMutationSession,
) -> Result<impl IntoResponse, AppError> {
    session::Entity::delete_by_id(mutation.0.session_digest)
        .exec(state.db.connection())
        .await?;
    let expired = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::ZERO)
        .build();
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired.to_string()).map_err(AppError::internal)?,
    );
    let csrf_expired = Cookie::build((CSRF_COOKIE, ""))
        .path("/")
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::ZERO)
        .build();
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_expired.to_string()).map_err(AppError::internal)?,
    );
    Ok((headers, axum::http::StatusCode::NO_CONTENT))
}

pub async fn revoke_user_sessions(state: &AppState, user_id: Uuid) -> Result<(), AppError> {
    session::Entity::delete_many()
        .filter(session::Column::UserId.eq(user_id.to_string()))
        .exec(state.db.connection())
        .await?;
    Ok(())
}

/// Signs the user out everywhere except the session making the request.
pub async fn revoke_other_sessions(
    state: &AppState,
    user_id: Uuid,
    keep_session_digest: &str,
) -> Result<(), AppError> {
    session::Entity::delete_many()
        .filter(session::Column::UserId.eq(user_id.to_string()))
        .filter(session::Column::Id.ne(keep_session_digest))
        .exec(state.db.connection())
        .await?;
    Ok(())
}

fn enrollment_required(state: &AppState, user: &PublicUser) -> bool {
    state.require_2fa.requires(user.role) && !user.two_factor_enabled
}

pub fn require_admin(user: &PublicUser) -> Result<(), AppError> {
    if user.role == Role::Admin && !user.disabled {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

impl FromRequestParts<AppState> for AuthenticatedSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = load_session(parts, state).await?;
        if session.two_factor_enrollment_required {
            return Err(AppError::TwoFactorEnrollmentRequired);
        }
        Ok(session)
    }
}

impl FromRequestParts<AppState> for PendingSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(load_session(parts, state).await?))
    }
}

impl FromRequestParts<AppState> for PendingMutationSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = load_session(parts, state).await?;
        require_csrf_header(parts, &session)?;
        Ok(Self(session))
    }
}

async fn load_session(parts: &Parts, state: &AppState) -> Result<AuthenticatedSession, AppError> {
    let token = cookie_value(&parts.headers, SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    let session_digest = digest(&token);
    let model = session::Entity::find_by_id(&session_digest)
        .one(state.db.connection())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if model.expires_at <= now() {
        session::Entity::delete_by_id(&session_digest)
            .exec(state.db.connection())
            .await?;
        return Err(AppError::Unauthorized);
    }
    let user_id = Uuid::parse_str(&model.user_id).map_err(AppError::internal)?;
    let user = UserRepository::new(state.db.clone()).get(user_id).await?;
    if user.disabled {
        return Err(AppError::Unauthorized);
    }
    let csrf_token = cookie_value(&parts.headers, CSRF_COOKIE).ok_or(AppError::Unauthorized)?;
    if digest(&csrf_token)
        .as_bytes()
        .ct_eq(model.csrf_digest.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AppError::Unauthorized);
    }
    Ok(AuthenticatedSession {
        user_id,
        csrf_digest: model.csrf_digest,
        csrf_token,
        session_digest,
        two_factor_enrollment_required: enrollment_required(state, &user),
        user,
    })
}

fn require_csrf_header(parts: &Parts, session: &AuthenticatedSession) -> Result<(), AppError> {
    let supplied = parts
        .headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Csrf)?;
    if digest(supplied)
        .as_bytes()
        .ct_eq(session.csrf_digest.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AppError::Csrf);
    }
    Ok(())
}

impl FromRequestParts<AppState> for MutationSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = AuthenticatedSession::from_request_parts(parts, state).await?;
        require_csrf_header(parts, &session)?;
        Ok(Self(session))
    }
}

async fn create_session(state: &AppState, user_id: Uuid) -> Result<(String, String), AppError> {
    session::Entity::delete_many()
        .filter(session::Column::ExpiresAt.lte(now()))
        .exec(state.db.connection())
        .await?;
    let token = random_token()?;
    let csrf_token = random_token()?;
    session::ActiveModel {
        id: Set(digest(&token)),
        user_id: Set(user_id.to_string()),
        csrf_digest: Set(digest(&csrf_token)),
        expires_at: Set(now() + SESSION_TTL_SECONDS),
        created_at: Set(now()),
    }
    .insert(state.db.connection())
    .await?;
    Ok((token, csrf_token))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

pub(crate) fn random_token() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    rand::rng()
        .try_fill_bytes(&mut bytes)
        .map_err(AppError::internal)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub(crate) fn second_factor_rate_key(client: Option<IpAddr>) -> String {
    format!(
        "second-factor|{}",
        client.map_or_else(|| "unknown".into(), |client| client.to_string())
    )
}

fn login_rate_key(username: &str, client: Option<IpAddr>) -> String {
    format!(
        "{}|{}",
        username.trim().to_lowercase(),
        client.map_or_else(|| "unknown".into(), |client| client.to_string())
    )
}

async fn check_login_rate(state: &AppState, key: &str) -> Result<(), AppError> {
    let mut failures = state.login_failures.lock().await;
    let cutoff = Instant::now() - Duration::from_secs(60);
    failures.retain(|_, attempts| {
        while attempts.front().is_some_and(|time| *time < cutoff) {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    if failures
        .get(key)
        .is_some_and(|attempts| attempts.len() >= 8)
    {
        return Err(AppError::RateLimited);
    }
    Ok(())
}

async fn record_login_failure(state: &AppState, key: &str) {
    let mut failures = state.login_failures.lock().await;
    if failures.len() >= 4096
        && !failures.contains_key(key)
        && let Some(oldest) = failures
            .iter()
            .min_by_key(|(_, attempts)| attempts.front().copied())
            .map(|(key, _)| key.clone())
    {
        failures.remove(&oldest);
    }
    let attempts = failures.entry(key.to_owned()).or_default();
    if attempts.len() < 8 {
        attempts.push_back(Instant::now());
    }
}

async fn clear_login_failures(state: &AppState, key: &str) {
    state.login_failures.lock().await.remove(key);
}
