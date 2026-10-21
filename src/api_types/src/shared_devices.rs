//! Requests and responses for registered shared devices and the PIN sign-in, see
//! `rauthy_data::entity::shared_devices`.

use rauthy_common::regex::{RE_ALNUM, RE_CLIENT_ID, RE_RESOURCE, RE_URI};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::{Validate, ValidationError};

use crate::cust_validation::validate_vec_scopes;

fn validate_label(value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ValidationError::new(
            "label must not be empty or contain control characters",
        ))
    } else {
        Ok(())
    }
}

fn validate_user_ids(ids: &[String]) -> Result<(), ValidationError> {
    if ids.len() > 50 {
        return Err(ValidationError::new("at most 50 user IDs"));
    }
    for id in ids {
        if id.is_empty() || id.len() > 64 || !RE_ALNUM.is_match(id) {
            return Err(ValidationError::new("user IDs must be alphanumeric"));
        }
    }
    Ok(())
}

fn validate_b64url(value: &str) -> Result<(), ValidationError> {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(ValidationError::new("base64url without padding"))
    }
}

fn validate_pin(pin: &str) -> Result<(), ValidationError> {
    if pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(ValidationError::new("the PIN has 4 digits"))
    }
}

/// `PUT /shared_devices/practices/{id}`
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct SharedDevicePracticeRequest {
    /// Shown on the login page and in E-Mails. Validation: 1-128 characters
    #[validate(length(min = 1, max = 128), custom(function = "validate_label"))]
    pub name: String,
    /// Seconds without activity before the PIN is needed again. Validation: `120..=900`,
    /// default `300`
    #[validate(range(min = 120, max = 900))]
    pub idle_timeout: Option<i64>,
    /// Users that get E-Mails about locked devices and changed IPs. Validation: at most 50
    #[validate(custom(function = "validate_user_ids"))]
    pub notify_user_ids: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDevicePracticeResponse {
    pub id: String,
    pub name: String,
    pub idle_timeout: i64,
    pub notify_user_ids: Vec<String>,
    /// Who confirmed the residual risk notice with the first device, and when
    pub risk_ack_by: Option<String>,
    pub risk_ack_at: Option<i64>,
    pub devices: Vec<SharedDeviceResponse>,
    pub members: Vec<SharedDeviceMemberResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceResponse {
    pub id: String,
    pub label: String,
    pub ip_registered: String,
    pub ip_lock: bool,
    /// Wrong PINs in a row
    pub failed_pins: i64,
    pub locked_at: Option<i64>,
    pub created_by: String,
    pub created: i64,
    pub last_seen: i64,
    pub last_seen_ip: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceMemberResponse {
    pub user_id: String,
    pub has_pin: bool,
    pub pin_created: Option<i64>,
    pub created: i64,
}

/// `PUT /shared_devices/devices/{id}`
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct SharedDeviceUpdateRequest {
    /// Validation: 1-64 characters
    #[validate(length(min = 1, max = 64), custom(function = "validate_label"))]
    pub label: String,
    /// If `true`, the device only works from the network it has been registered in
    pub ip_lock: bool,
}

/// `POST /shared_devices/practices/{id}/registrations`
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct SharedDeviceRegistrationRequest {
    /// The user who registers the device in its own browser with a fresh passkey
    #[validate(
        length(min = 1, max = 64),
        regex(path = "*RE_ALNUM", code = "^[a-zA-Z0-9]+$")
    )]
    pub user_id: String,
    /// Validation: 1-64 characters
    #[validate(length(min = 1, max = 64), custom(function = "validate_label"))]
    pub label: String,
    /// Where the registration page links back to. Must have the origin of a redirect URI of a
    /// client in `shared_devices.client_ids`.
    #[validate(
        length(max = 512),
        regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$")
    )]
    pub return_uri: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceRegistrationResponse {
    pub id: String,
    /// Open this in the browser of the device
    pub url: String,
    pub exp: i64,
}

/// `GET /shared_devices/registrations/{id}`, only for the user of the registration
#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceRegistrationInfoResponse {
    pub practice_name: String,
    pub label: String,
    /// The first device of a practice needs the residual risk notice to be confirmed
    pub needs_risk_ack: bool,
    pub return_uri: Option<String>,
    pub exp: i64,
}

/// `POST /shared_devices/registrations/{id}`
#[derive(Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct SharedDeviceRegisterRequest {
    /// A fresh `MfaModToken` from a passkey of this user, see `POST /users/{id}/mfa_token`
    #[validate(length(min = 32, max = 32))]
    pub mfa_mod_token_id: String,
    /// The browser's ECDSA P-256 public key, uncompressed point, base64url without padding
    #[validate(length(min = 1, max = 128), custom(function = "validate_b64url"))]
    pub public_key: String,
    /// Signature of the registration ID with this key, base64url without padding
    #[validate(length(min = 1, max = 128), custom(function = "validate_b64url"))]
    pub signature: String,
    pub risk_ack: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceRegisterResponse {
    pub device_id: String,
    pub return_uri: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceChallengeResponse {
    pub id: String,
    /// Sign these UTF-8 bytes with the device key
    pub challenge: String,
}

/// The device of this browser on the login page, `<template id="tpl_shared_device">`
#[derive(Debug, Serialize)]
pub struct SharedDeviceTemplate<'a> {
    pub label: &'a str,
    pub practice: &'a str,
    pub locked: bool,
    /// `false` if this client does not accept a PIN, or the request asks for a fresh passkey
    /// with `max_age`
    pub pin: bool,
}

/// `POST /oidc/authorize/pin`. No `Debug` on purpose: the PIN must never end up in a log.
#[derive(Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct PinLoginRequest {
    /// Validation: 4 digits
    #[validate(custom(function = "validate_pin"))]
    pub pin: String,
    /// Validation: `[a-zA-Z0-9]{32}`
    #[validate(
        length(min = 32, max = 32),
        regex(path = "*RE_ALNUM", code = "^[a-zA-Z0-9]+$")
    )]
    pub challenge_id: String,
    /// Signature of the challenge with the device key, base64url without padding
    #[validate(length(min = 1, max = 128), custom(function = "validate_b64url"))]
    pub signature: String,
    /// Validation: `^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,128}$`
    #[validate(regex(
        path = "*RE_CLIENT_ID",
        code = "^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]{2,128}$"
    ))]
    pub client_id: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub redirect_uri: String,
    /// Validation: `Vec<^[a-z0-9-_/,:*]{2,64}$>`
    #[validate(custom(function = "validate_vec_scopes"))]
    pub scopes: Option<Vec<String>>,
    /// Validation: max length 2048
    #[validate(length(max = 2048))]
    pub state: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub nonce: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub code_challenge: Option<String>,
    /// Validation: `plain|S256`
    #[validate(regex(
        path = "*rauthy_common::regex::RE_CODE_CHALLENGE_METHOD",
        code = "plain|S256"
    ))]
    pub code_challenge_method: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~!$'()*+%@]+$`
    #[validate(regex(path = "*RE_RESOURCE", code = "[a-zA-Z0-9,.:/_-&?=~!$'()*+%@]+$"))]
    pub resource: Option<String>,
}

/// A failed PIN login. `error` is `wrong_pin` (with `remaining` attempts), `locked`, or
/// `invalid_device`.
#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct PinLoginErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining: Option<i64>,
}

/// `GET /users/{id}/shared_device_pins`
#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDevicePinInfoResponse {
    pub practice_id: String,
    pub practice_name: String,
    /// When the current PIN was created, `None` without a PIN
    pub pin_created: Option<i64>,
}

/// `POST /users/{id}/shared_device_pins/{practice_id}`
#[derive(Deserialize, Validate, ToSchema)]
pub struct SharedDevicePinGenerateRequest {
    /// A fresh `MfaModToken` from a passkey of this user, see `POST /users/{id}/mfa_token`
    #[validate(length(min = 32, max = 32))]
    pub mfa_mod_token_id: String,
}

/// No `Debug` on purpose: the PIN must never end up in a log.
#[derive(Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDevicePinResponse {
    /// Shown exactly once
    pub pin: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema, IntoParams)]
pub struct SharedDeviceEventsParams {
    /// Validation: `1..=1000`, default `100`
    #[validate(range(min = 1, max = 1000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[cfg_attr(debug_assertions, derive(Deserialize))]
pub struct SharedDeviceEventResponse {
    pub id: String,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    /// `registered`, `revoked`, `pin_login`, `passkey_login`, `other_login`, `pin_failed`,
    /// `locked`, `unlocked`, `ip_changed`, `ip_blocked`, `pin_changed`
    pub kind: String,
    pub ip: Option<String>,
    pub created: i64,
}
