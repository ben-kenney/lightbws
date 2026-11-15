//! Self-service second-factor enrolment and password change for the signed-in user.
//!
//! Enrolment routes accept a session that still owes a required second factor, because they are
//! how that user gets one. Every change is confirmed with the current password, a current code,
//! or both, so a borrowed session cannot quietly swap or remove the second factor.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{
        AuthenticatedSession, MutationSession, PendingMutationSession, PendingSession,
        revoke_other_sessions,
    },
    domain::{
        audit::{AuditActor, AuditRepository},
        two_factor::{SecondFactorProof, TotpEnrollment, TwoFactorStatus},
        users::{UserRepository, verify_password},
    },
    error::AppError,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeInput {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordAndCodeInput {
    password: String,
    /// Required when the account has an authenticator app; passkey-only accounts omit it.
    #[serde(default)]
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DisableInput {
    password: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePasswordInput {
    current_password: String,
    new_password: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCodes {
    recovery_codes: Vec<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route("/totp/setup", post(setup_totp))
        .route("/totp/confirm", post(confirm_totp))
        .route("/totp", delete(disable_totp))
        .route(
            "/recovery-codes/regenerate",
            post(regenerate_recovery_codes),
        )
}

async fn status(
    State(state): State<AppState>,
    PendingSession(session): PendingSession,
) -> Result<Json<TwoFactorStatus>, AppError> {
    Ok(Json(
        state
            .two_factor()
            .status(
                session.user_id,
                state.require_2fa.requires(session.user.role),
            )
            .await?,
    ))
}

async fn setup_totp(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Json(input): Json<PasswordInput>,
) -> Result<Json<TotpEnrollment>, AppError> {
    confirm_password(&state, &session, input.password).await?;
    Ok(Json(
        state
            .two_factor()
            .begin_totp(session.user_id, &session.user.username)
            .await?,
    ))
}

async fn confirm_totp(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Json(input): Json<CodeInput>,
) -> Result<Json<RecoveryCodes>, AppError> {
    let rate_key = reauth_rate_key(session.user_id);
    require_attempts_left(&state, &rate_key)?;
    let Some(recovery_codes) = state
        .two_factor()
        .confirm_totp(session.user_id, &input.code)
        .await?
    else {
        state.second_factor_failures.record_failure(&rate_key);
        return Err(AppError::InvalidCredentials);
    };
    // Anyone else holding a session for this account signed in without the new factor.
    revoke_other_sessions(&state, session.user_id, &session.session_digest).await?;
    record(&state, session.user_id, "user.2fa.enable").await?;
    Ok(Json(RecoveryCodes { recovery_codes }))
}

async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Json(input): Json<PasswordAndCodeInput>,
) -> Result<Json<RecoveryCodes>, AppError> {
    confirm_password(&state, &session, input.password).await?;
    let status = state.two_factor().status(session.user_id, false).await?;
    if !status.enabled {
        return Err(AppError::Conflict);
    }
    if status.totp_enabled {
        confirm_second_factor(&state, &session, input.code.as_deref(), None).await?;
    }
    let recovery_codes = state
        .two_factor()
        .regenerate_recovery_codes(session.user_id)
        .await?;
    record(
        &state,
        session.user_id,
        "user.2fa.recovery_codes.regenerate",
    )
    .await?;
    Ok(Json(RecoveryCodes { recovery_codes }))
}

async fn disable_totp(
    State(state): State<AppState>,
    PendingMutationSession(session): PendingMutationSession,
    Json(input): Json<DisableInput>,
) -> Result<StatusCode, AppError> {
    if state.require_2fa.requires(session.user.role)
        && state
            .two_factor()
            .status(session.user_id, true)
            .await?
            .passkey_count
            == 0
    {
        return Err(AppError::Validation(
            "two-factor authentication is required for this account".into(),
        ));
    }
    confirm_password(&state, &session, input.password).await?;
    confirm_second_factor(
        &state,
        &session,
        input.code.as_deref(),
        input.recovery_code.as_deref(),
    )
    .await?;
    if state.two_factor().disable_totp(session.user_id).await? {
        record(&state, session.user_id, "user.2fa.disable").await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Lets a user change their own password. Needs the current password and, when a second factor
/// is set up, a current code or a recovery code. Other sessions of the user are signed out.
pub async fn change_password(
    State(state): State<AppState>,
    MutationSession(session): MutationSession,
    Json(input): Json<ChangePasswordInput>,
) -> Result<StatusCode, AppError> {
    confirm_password(&state, &session, input.current_password).await?;
    // A passkey cannot be typed into a form; the password is the confirmation for an account
    // whose only second factor is a passkey.
    if state
        .two_factor()
        .status(session.user_id, false)
        .await?
        .totp_enabled
    {
        confirm_second_factor(
            &state,
            &session,
            input.code.as_deref(),
            input.recovery_code.as_deref(),
        )
        .await?;
    }
    UserRepository::new(state.db.clone())
        .reset_password(session.user_id, &input.new_password)
        .await?;
    revoke_other_sessions(&state, session.user_id, &session.session_digest).await?;
    record(&state, session.user_id, "user.password.change").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Checks the signed-in user's password. Failures are limited per user, so a borrowed session
/// cannot be used to guess the password.
pub(super) async fn confirm_password(
    state: &AppState,
    session: &AuthenticatedSession,
    password: String,
) -> Result<(), AppError> {
    let rate_key = reauth_rate_key(session.user_id);
    require_attempts_left(state, &rate_key)?;
    let model = UserRepository::new(state.db.clone())
        .find_model(&session.user_id.to_string())
        .await?
        .ok_or(AppError::Unauthorized)?;
    let valid =
        tokio::task::spawn_blocking(move || verify_password(&model.password_hash, &password))
            .await
            .map_err(AppError::internal)?;
    if !valid {
        state.second_factor_failures.record_failure(&rate_key);
        return Err(AppError::InvalidCredentials);
    }
    Ok(())
}

async fn confirm_second_factor(
    state: &AppState,
    session: &AuthenticatedSession,
    code: Option<&str>,
    recovery_code: Option<&str>,
) -> Result<(), AppError> {
    let proof = match (code, recovery_code) {
        (Some(code), None) => SecondFactorProof::Totp(code),
        (None, Some(code)) => SecondFactorProof::RecoveryCode(code),
        _ => {
            return Err(AppError::Validation(
                "provide either a code or a recovery code".into(),
            ));
        }
    };
    let rate_key = reauth_rate_key(session.user_id);
    require_attempts_left(state, &rate_key)?;
    if state
        .two_factor()
        .verify(session.user_id, proof)
        .await?
        .is_none()
    {
        state.second_factor_failures.record_failure(&rate_key);
        return Err(AppError::InvalidCredentials);
    }
    if matches!(proof, SecondFactorProof::RecoveryCode(_)) {
        record(state, session.user_id, "user.2fa.recovery_code.used").await?;
    }
    Ok(())
}

fn require_attempts_left(state: &AppState, rate_key: &str) -> Result<(), AppError> {
    if state.second_factor_failures.check(rate_key) {
        Ok(())
    } else {
        Err(AppError::RateLimited)
    }
}

fn reauth_rate_key(user_id: Uuid) -> String {
    format!("confirm|{user_id}")
}

pub(super) async fn record(state: &AppState, user_id: Uuid, action: &str) -> Result<(), AppError> {
    AuditRepository::new(state.db.clone())
        .record(
            AuditActor::User(user_id),
            action,
            "user",
            Some(user_id),
            "changed",
        )
        .await
}
