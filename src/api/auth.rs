use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, auth};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/config", get(auth::config))
        .route("/login", post(auth::login))
        .route("/login/2fa", post(auth::login_second_factor))
        .route("/session", get(auth::current))
        .route("/logout", post(auth::logout))
        .route("/password", post(super::two_factor::change_password))
        .nest("/2fa", super::two_factor::routes())
        .nest("/passkeys", super::passkeys::routes())
        .merge(super::passkeys::login_routes())
}
