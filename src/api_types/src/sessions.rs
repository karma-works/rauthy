use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(PartialEq, Serialize, Deserialize, ToSchema)]
pub enum SessionState {
    Init,
    Auth,
    LoggedOut,
    Unknown,
}

#[derive(Serialize, ToSchema)]
pub struct SessionResponse<'a> {
    pub id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<&'a str>,
    pub is_mfa: bool,
    pub state: SessionState,
    /// Unix timestamp in seconds
    pub exp: i64,
    /// Unix timestamp in seconds
    pub last_seen: i64,
    pub remote_ip: Option<&'a str>,
}

/// One of the user's own sessions, for `GET /users/{id}/sessions`. It contains no session ID and
/// no IP address on purpose.
#[derive(Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct UserSessionResponse {
    /// `true` for the session that made this request
    pub current: bool,
    /// A coarse "Browser · OS" label, if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// `true` if the login used a passkey or another second factor
    pub is_mfa: bool,
    /// Unix timestamp in seconds
    pub last_seen: i64,
    /// Unix timestamp in seconds
    pub exp: i64,
}

/// `DELETE /users/{id}/sessions`
#[derive(Deserialize, validator::Validate, ToSchema)]
pub struct UserSessionsDeleteRequest {
    /// A fresh `MfaModToken` of this user, see `POST /users/{id}/mfa_token`
    #[validate(length(min = 32, max = 32))]
    pub mfa_mod_token_id: String,
}
