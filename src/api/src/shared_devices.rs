//! Registered shared devices (practice PCs) and the PIN sign-in, see
//! `rauthy_data::entity::shared_devices`. Everything returns `404` unless
//! `shared_devices.enable`.

use crate::{ReqPrincipal, map_auth_step};
use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::web::{Json, Query};
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};
use rauthy_api_types::shared_devices::{
    PinLoginErrorResponse, PinLoginRequest, SharedDeviceChallengeResponse,
    SharedDeviceEventResponse, SharedDeviceEventsParams, SharedDeviceMemberResponse,
    SharedDevicePinGenerateRequest, SharedDevicePinInfoResponse, SharedDevicePinResponse,
    SharedDevicePracticeRequest, SharedDevicePracticeResponse, SharedDeviceRegisterRequest,
    SharedDeviceRegisterResponse, SharedDeviceRegistrationInfoResponse,
    SharedDeviceRegistrationRequest, SharedDeviceRegistrationResponse, SharedDeviceResponse,
    SharedDeviceUpdateRequest,
};
use rauthy_common::constants::COOKIE_SESSION;
use rauthy_common::utils::{base64_url_no_pad_decode, real_ip_from_req};
use rauthy_data::api_cookie::ApiCookie;
use rauthy_data::entity::api_keys::{AccessGroup, AccessRights};
use rauthy_data::entity::auth_providers::NewFederatedUserCreated;
use rauthy_data::entity::mfa_mod_token::MfaModToken;
use rauthy_data::entity::practice_roles::{self, PracticeRole};
use rauthy_data::entity::refresh_tokens::RefreshToken;
use rauthy_data::entity::sessions::SessionState;
use rauthy_data::entity::shared_devices::{
    IDLE_TIMEOUT_DEFAULT, PIN_MAX_FAILURES, SharedDevice, SharedDeviceChallenge, SharedDeviceEvent,
    SharedDeviceEventKind, SharedDeviceMember, SharedDevicePractice, SharedDeviceRegistration,
    check_enabled, is_pin_client, validate_public_key, validate_return_uri, verify_signature,
};
use rauthy_data::entity::users::User;
use rauthy_data::rauthy_config::RauthyConfig;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use rauthy_service::oidc::authorize;
use tracing::{info, warn};
use validator::Validate;

/// Practice IDs come from an external system, like an organization UUID.
fn validate_practice_id(id: &str) -> Result<(), ErrorResponse> {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Invalid practice ID",
        ))
    }
}

fn no_store(resp: &mut actix_web::HttpResponseBuilder) -> &mut actix_web::HttpResponseBuilder {
    resp.insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((PRAGMA, "no-cache"))
}

fn device_response(d: SharedDevice) -> SharedDeviceResponse {
    SharedDeviceResponse {
        id: d.id,
        label: d.label,
        ip_registered: d.ip_registered,
        ip_lock: d.ip_lock,
        failed_pins: d.failed_pins,
        locked_at: d.locked_at,
        created_by: d.created_by,
        created: d.created,
        last_seen: d.last_seen,
        last_seen_ip: d.last_seen_ip,
    }
}

async fn practice_response(
    practice: SharedDevicePractice,
) -> Result<SharedDevicePracticeResponse, ErrorResponse> {
    let devices = SharedDevice::find_for_practice(&practice.id)
        .await?
        .into_iter()
        .map(device_response)
        .collect();
    let members = SharedDeviceMember::find_for_practice(&practice.id)
        .await?
        .into_iter()
        .map(|m| SharedDeviceMemberResponse {
            has_pin: m.pin_hmac.is_some(),
            user_id: m.user_id,
            pin_created: m.pin_created,
            created: m.created,
        })
        .collect();
    Ok(SharedDevicePracticeResponse {
        role_mode: practice_roles::enabled(&practice.id).await?,
        notify_user_ids: practice
            .notify_user_ids()
            .into_iter()
            .map(String::from)
            .collect(),
        idle_timeout: practice.idle_timeout(),
        id: practice.id,
        name: practice.name,
        risk_ack_by: practice.risk_ack_by,
        risk_ack_at: practice.risk_ack_at,
        devices,
        members,
    })
}

// ##################################################################################
// Admin API
// ##################################################################################

/// Create or update a practice for shared devices
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Update`
#[utoipa::path(
    put,
    path = "/shared_devices/practices/{id}",
    tag = "shared_devices",
    request_body = SharedDevicePracticeRequest,
    responses(
        (status = 200, description = "Ok", body = SharedDevicePracticeResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[put("/shared_devices/practices/{id}")]
pub async fn put_practice(
    path: web::Path<String>,
    principal: ReqPrincipal,
    Json(payload): Json<SharedDevicePracticeRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Update)?;
    payload.validate()?;
    let id = path.into_inner();
    validate_practice_id(&id)?;

    let practice = SharedDevicePractice::upsert(
        id,
        payload.name.trim().to_string(),
        payload.idle_timeout.unwrap_or(IDLE_TIMEOUT_DEFAULT),
        payload.notify_user_ids,
    )
    .await?;
    Ok(HttpResponse::Ok().json(practice_response(practice).await?))
}

/// A practice with its devices and members
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Read`
#[utoipa::path(
    get,
    path = "/shared_devices/practices/{id}",
    tag = "shared_devices",
    responses(
        (status = 200, description = "Ok", body = SharedDevicePracticeResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[get("/shared_devices/practices/{id}")]
pub async fn get_practice(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Read)?;
    let id = path.into_inner();
    validate_practice_id(&id)?;

    let practice = SharedDevicePractice::find(&id).await?;
    Ok(HttpResponse::Ok().json(practice_response(practice).await?))
}

/// Delete a practice with all its devices, members and events
///
/// Ends all sessions on its devices.
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Delete`
#[utoipa::path(
    delete,
    path = "/shared_devices/practices/{id}",
    tag = "shared_devices",
    responses(
        (status = 204, description = "NoContent"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[delete("/shared_devices/practices/{id}")]
pub async fn delete_practice(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Delete)?;
    let id = path.into_inner();
    validate_practice_id(&id)?;

    SharedDevicePractice::delete(&id).await?;
    info!(practice_id = id, "shared device practice deleted");
    Ok(HttpResponse::NoContent().finish())
}

/// Allow a user to have a PIN on the devices of a practice
///
/// Does nothing if the user is a member already.
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Update`
#[utoipa::path(
    put,
    path = "/shared_devices/practices/{id}/members/{user_id}",
    tag = "shared_devices",
    responses(
        (status = 204, description = "NoContent"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[put("/shared_devices/practices/{id}/members/{user_id}")]
pub async fn put_practice_member(
    path: web::Path<(String, String)>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Update)?;
    let (id, user_id) = path.into_inner();
    validate_practice_id(&id)?;

    SharedDevicePractice::find(&id).await?;
    User::find(user_id.clone()).await?;
    SharedDeviceMember::add(&id, &user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Remove a member with its PIN
///
/// Ends the member's sessions on the devices of the practice.
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Delete`
#[utoipa::path(
    delete,
    path = "/shared_devices/practices/{id}/members/{user_id}",
    tag = "shared_devices",
    responses(
        (status = 204, description = "NoContent"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[delete("/shared_devices/practices/{id}/members/{user_id}")]
pub async fn delete_practice_member(
    path: web::Path<(String, String)>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Delete)?;
    let (id, user_id) = path.into_inner();
    validate_practice_id(&id)?;

    SharedDeviceMember::remove(&id, &user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// The security events of a practice, newest first
///
/// Kept for 90 days.
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Read`
#[utoipa::path(
    get,
    path = "/shared_devices/practices/{id}/events",
    tag = "shared_devices",
    params(SharedDeviceEventsParams),
    responses(
        (status = 200, description = "Ok", body = [SharedDeviceEventResponse]),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[get("/shared_devices/practices/{id}/events")]
pub async fn get_practice_events(
    path: web::Path<String>,
    principal: ReqPrincipal,
    Query(params): Query<SharedDeviceEventsParams>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Read)?;
    params.validate()?;
    let id = path.into_inner();
    validate_practice_id(&id)?;

    let events = SharedDeviceEvent::find_for_practice(&id, params.limit.unwrap_or(100))
        .await?
        .into_iter()
        .map(|e| SharedDeviceEventResponse {
            role: e.role,
            id: e.id,
            device_id: e.device_id,
            user_id: e.user_id,
            kind: e.kind,
            ip: e.ip,
            created: e.created,
        })
        .collect::<Vec<_>>();
    Ok(HttpResponse::Ok().json(events))
}

/// Start the registration of a device
///
/// `user_id` opens the returned `url` in the browser of the device within 10 minutes, signs in
/// there with a fresh passkey and confirms. The registration can only be used once and only by
/// this user, in a browser where the user has a session.
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Create`
#[utoipa::path(
    post,
    path = "/shared_devices/practices/{id}/registrations",
    tag = "shared_devices",
    request_body = SharedDeviceRegistrationRequest,
    responses(
        (status = 200, description = "Ok", body = SharedDeviceRegistrationResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[post("/shared_devices/practices/{id}/registrations")]
pub async fn post_practice_registration(
    path: web::Path<String>,
    principal: ReqPrincipal,
    Json(payload): Json<SharedDeviceRegistrationRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Create)?;
    payload.validate()?;
    let id = path.into_inner();
    validate_practice_id(&id)?;

    SharedDevicePractice::find(&id).await?;
    if practice_roles::enabled(&id).await? {
        for role in practice_roles::ROLES {
            if PracticeRole::find(&id, role)
                .await?
                .is_none_or(|r| r.pin_hmac.is_none())
            {
                return Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "Configure all three role PINs before coupling",
                ));
            }
        }
    }
    let user = User::find(payload.user_id).await?;
    if !user.has_webauthn_enabled() && !RauthyConfig::get().vars.shared_devices.password_login {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The user needs a passkey to register a device",
        ));
    }
    if let Some(uri) = &payload.return_uri {
        validate_return_uri(uri).await?;
    }

    let reg = SharedDeviceRegistration::create(
        id,
        user.id,
        payload.label.trim().to_string(),
        payload.return_uri,
    )
    .await?;
    let url = format!(
        "{}shared_devices/register?id={}",
        RauthyConfig::get().issuer,
        reg.id
    );
    Ok(
        no_store(&mut HttpResponse::Ok()).json(SharedDeviceRegistrationResponse {
            id: reg.id,
            url,
            exp: reg.exp,
        }),
    )
}

/// Rename a device or change its IP rule
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Update`
#[utoipa::path(
    put,
    path = "/shared_devices/devices/{id}",
    tag = "shared_devices",
    request_body = SharedDeviceUpdateRequest,
    responses(
        (status = 204, description = "NoContent"),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[put("/shared_devices/devices/{id}")]
pub async fn put_device(
    path: web::Path<String>,
    principal: ReqPrincipal,
    Json(payload): Json<SharedDeviceUpdateRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Update)?;
    payload.validate()?;

    let device = SharedDevice::find(&path.into_inner()).await?;
    device.update(payload.label.trim(), payload.ip_lock).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Revoke a device
///
/// Ends all sessions on it. The browser falls back to the normal login.
///
/// **Permissions**
/// - `rauthy_admin` or API key `SharedDevices: Delete`
#[utoipa::path(
    delete,
    path = "/shared_devices/devices/{id}",
    tag = "shared_devices",
    responses(
        (status = 204, description = "NoContent"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[delete("/shared_devices/devices/{id}")]
pub async fn delete_device(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Delete)?;

    let device = SharedDevice::find(&path.into_inner()).await?;
    device.delete().await?;
    SharedDeviceEvent::create(
        &device.practice_id,
        Some(&device.id),
        None,
        SharedDeviceEventKind::Revoked,
        None,
    )
    .await?;
    info!(device_id = device.id, "shared device revoked");
    Ok(HttpResponse::NoContent().finish())
}

// ##################################################################################
// Registration in the browser of the device
// ##################################################################################

async fn registration_for_session(
    id: &str,
    principal: &ReqPrincipal,
) -> Result<SharedDeviceRegistration, ErrorResponse> {
    let session = principal.validate_session_auth()?;
    let reg = SharedDeviceRegistration::find(id).await?;
    // Someone else's link must not even reveal the practice.
    if session.user_id.as_deref() != Some(reg.user_id.as_str()) {
        return Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "The registration does not exist or has expired",
        ));
    }
    Ok(reg)
}

/// The registration of a device, for its user
///
/// **Permissions**
/// - authenticated session of the user of the registration
#[utoipa::path(
    get,
    path = "/shared_devices/registrations/{id}",
    tag = "shared_devices",
    responses(
        (status = 200, description = "Ok", body = SharedDeviceRegistrationInfoResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[get("/shared_devices/registrations/{id}")]
pub async fn get_registration(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    let reg = registration_for_session(&path.into_inner(), &principal).await?;
    let practice = SharedDevicePractice::find(&reg.practice_id).await?;
    Ok(
        no_store(&mut HttpResponse::Ok()).json(SharedDeviceRegistrationInfoResponse {
            practice_name: practice.name,
            label: reg.label,
            needs_risk_ack: practice.risk_ack_at.is_none(),
            password_allowed: RauthyConfig::get().vars.shared_devices.password_login,
            return_uri: reg.return_uri,
            exp: reg.exp,
        }),
    )
}

/// Register this browser as a shared device
///
/// Needs the session of the registration's user and a fresh `MfaModToken` from a passkey, which
/// is consumed. The browser proves the possession of its key with a signature of the
/// registration ID. Sets the device cookie. A device that was registered in this browser before
/// is revoked.
///
/// **Permissions**
/// - authenticated session of the user of the registration
#[utoipa::path(
    post,
    path = "/shared_devices/registrations/{id}",
    tag = "shared_devices",
    request_body = SharedDeviceRegisterRequest,
    responses(
        (status = 200, description = "Ok", body = SharedDeviceRegisterResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
#[post("/shared_devices/registrations/{id}")]
pub async fn post_registration(
    req: HttpRequest,
    path: web::Path<String>,
    principal: ReqPrincipal,
    Json(payload): Json<SharedDeviceRegisterRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    payload.validate()?;
    let reg = registration_for_session(&path.into_inner(), &principal).await?;
    let session = principal.validate_session_auth()?.clone();

    let ip = real_ip_from_req(&req)?;
    let token = if let Some(password) = payload.password.as_ref() {
        if !RauthyConfig::get().vars.shared_devices.password_login {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "Password login disabled",
            ));
        }
        practice_roles::validate_account_password(
            &User::find(reg.user_id.clone()).await?,
            password.clone(),
        )
        .await?;
        None
    } else {
        let token =
            MfaModToken::find(payload.mfa_mod_token_id.as_deref().unwrap_or_default()).await?;
        token.validate(&reg.user_id, ip)?;
        Some(token)
    };
    let user = User::find(reg.user_id.clone()).await?;
    // Keep the account passkey even when it confirms this coupling with its password.
    if !user.has_webauthn_enabled() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "A passkey is needed to register a device",
        ));
    }

    let practice = SharedDevicePractice::find(&reg.practice_id).await?;
    if practice.risk_ack_at.is_none() && !payload.risk_ack {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The residual risk notice must be confirmed for the first device",
        ));
    }

    let public_key = base64_url_no_pad_decode(&payload.public_key)?;
    validate_public_key(&public_key)?;
    let signature = base64_url_no_pad_decode(&payload.signature)?;
    if !verify_signature(&public_key, reg.id.as_bytes(), &signature) {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Invalid signature of the device key",
        ));
    }

    if let Some(token) = token {
        token.delete().await?;
    }
    reg.delete().await?;

    if let Some(old) = SharedDevice::from_req(&req).await? {
        info!(
            device_id = old.id,
            "replacing the device registered in this browser"
        );
        old.delete().await?;
        SharedDeviceEvent::create(
            &old.practice_id,
            Some(&old.id),
            Some(&user.id),
            SharedDeviceEventKind::Revoked,
            Some(&ip.to_string()),
        )
        .await?;
    }

    if practice.risk_ack_at.is_none() {
        practice.ack_risk(&user.id).await?;
    }

    let (device, device_token) = SharedDevice::create(
        practice.id.clone(),
        reg.label,
        public_key,
        ip.to_string(),
        user.id.clone(),
    )
    .await?;
    SharedDeviceEvent::create(
        &practice.id,
        Some(&device.id),
        Some(&user.id),
        SharedDeviceEventKind::Registered,
        Some(&ip.to_string()),
    )
    .await?;

    // The session of the registering person must not stay open on a shared device.
    let sid = session.id.clone();
    session.invalidate().await?;
    RefreshToken::delete_by_sid(sid).await?;

    info!(
        device_id = device.id,
        practice_id = practice.id,
        "shared device registered"
    );
    Ok(no_store(&mut HttpResponse::Ok())
        .cookie(SharedDevice::build_cookie(&device_token))
        .cookie(ApiCookie::build(COOKIE_SESSION, "", 0))
        .json(SharedDeviceRegisterResponse {
            device_id: device.id,
            return_uri: reg.return_uri,
        }))
}

/// A challenge for the next PIN login, to be signed with the device key
///
/// **Permissions**
/// - the device cookie of a registered device
#[utoipa::path(
    post,
    path = "/shared_devices/challenge",
    tag = "shared_devices",
    responses(
        (status = 200, description = "Ok", body = SharedDeviceChallengeResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
#[post("/shared_devices/challenge")]
pub async fn post_challenge(req: HttpRequest) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    let device = SharedDevice::from_req(&req).await?.ok_or_else(|| {
        ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "This browser is not a registered device",
        )
    })?;
    let challenge = SharedDeviceChallenge::create(device.id).await?;
    Ok(
        no_store(&mut HttpResponse::Ok()).json(SharedDeviceChallengeResponse {
            id: challenge.id,
            challenge: challenge.challenge,
        }),
    )
}

// ##################################################################################
// PIN login
// ##################################################################################

fn pin_error(status: StatusCode, error: &str, remaining: Option<i64>) -> HttpResponse {
    no_store(&mut HttpResponse::build(status)).json(PinLoginErrorResponse {
        error: error.to_string(),
        remaining,
    })
}

/// Login with a PIN on a registered shared device
///
/// Continues the `authorization_code` flow from `GET /oidc/authorize` like `POST /oidc/authorize`.
/// Needs the session of the login page and the device cookie, both of the same device, and a
/// challenge signed with the device key. On success, it returns `202` with the `Location`
/// header.
///
/// Errors:
/// - `401` `{"error": "wrong_pin", "remaining": 3}`
/// - `401` `{"error": "invalid_device"}`: no device, another session, invalid signature
/// - `423` `{"error": "locked"}`: a member has to sign in with a passkey to unlock the device
/// - `403`: the client accepts no PIN, or the device may not be used from this network
///
/// **Permissions**
/// - `session-init`
/// - `session-auth`
#[utoipa::path(
    post,
    path = "/oidc/authorize/pin",
    tag = "oidc",
    request_body = PinLoginRequest,
    responses(
        (status = 202, description = "Accepted, with the Location header"),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = PinLoginErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 423, description = "Locked", body = PinLoginErrorResponse),
    ),
)]
#[post("/oidc/authorize/pin")]
pub async fn post_authorize_pin(
    req: HttpRequest,
    principal: ReqPrincipal,
    Json(payload): Json<PinLoginRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_session_auth_or_init()?;
    payload.validate()?;
    let session = principal.get_session()?.clone();
    let ip = real_ip_from_req(&req)?.to_string();

    let (Some(device_token), Some(device)) = (
        SharedDevice::token_from_req(&req),
        SharedDevice::from_req(&req).await?,
    ) else {
        return Ok(pin_error(StatusCode::UNAUTHORIZED, "invalid_device", None));
    };
    // Only the fresh login session of this very device, never an authenticated one that could
    // still carry tokens of somebody else.
    if session.shared_device_id.as_deref() != Some(device.id.as_str())
        || session.state != SessionState::Init
    {
        warn!(
            device_id = device.id,
            "PIN login with a session of another device"
        );
        return Ok(pin_error(StatusCode::UNAUTHORIZED, "invalid_device", None));
    }
    if !is_pin_client(&payload.client_id) {
        return Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "This client does not accept a PIN",
        ));
    }

    // The signature proves the device key, so a copied cookie alone is not enough.
    let Ok(challenge) = SharedDeviceChallenge::take(&payload.challenge_id, &device.id).await else {
        return Ok(pin_error(StatusCode::UNAUTHORIZED, "invalid_device", None));
    };
    let signature = base64_url_no_pad_decode(&payload.signature)?;
    if !verify_signature(
        &device.public_key,
        challenge.challenge.as_bytes(),
        &signature,
    ) {
        warn!(
            device_id = device.id,
            "PIN login with an invalid device signature"
        );
        return Ok(pin_error(StatusCode::UNAUTHORIZED, "invalid_device", None));
    }

    device.check_ip(&ip).await?;
    let selected_role = payload.role.clone();
    let user = if let Some(role) = selected_role.as_deref() {
        practice_roles::validate_role(role)?;
        if !practice_roles::enabled(&device.practice_id).await? {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "Role mode disabled",
            ));
        }
        let Some(attempt) = practice_roles::reserve(&device.id, role).await? else {
            return Ok(pin_error(StatusCode::LOCKED, "locked", None));
        };
        let configured = PracticeRole::find(&device.practice_id, role).await?;
        let pin_version = configured
            .as_ref()
            .map(|r| r.pin_version)
            .unwrap_or_default();
        let user = if let Some(configured) = configured {
            if configured.matches(&payload.pin)? {
                User::find(configured.user_id)
                    .await
                    .ok()
                    .filter(|u| u.check_enabled().is_ok() && u.check_expired().is_ok())
            } else {
                None
            }
        } else {
            None
        };
        practice_roles::finish_attempt(&device.id, role, user.is_some()).await?;
        let Some(user) = user else {
            SharedDeviceEvent::create_context(
                &device.practice_id,
                Some(&device.id),
                None,
                SharedDeviceEventKind::PinFailed,
                Some(&ip),
                Some(role),
            )
            .await?;
            return Ok(if attempt >= PIN_MAX_FAILURES {
                pin_error(StatusCode::LOCKED, "locked", None)
            } else {
                pin_error(
                    StatusCode::UNAUTHORIZED,
                    "wrong_pin",
                    Some(PIN_MAX_FAILURES - attempt),
                )
            });
        };
        practice_roles::bind(&session.id, &device.practice_id, role, pin_version).await?;
        user
    } else {
        // Once role mode is enabled, personal PINs cannot bypass the selected role.
        if practice_roles::enabled(&device.practice_id).await? {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "Select a practice role",
            ));
        }
        let Some(attempt) = device.reserve_attempt(&ip).await? else {
            return Ok(pin_error(StatusCode::LOCKED, "locked", None));
        };

        // The PIN of a disabled or expired account counts like a wrong one.
        let user = match SharedDeviceMember::find_by_pin(&device.practice_id, &payload.pin).await? {
            Some(user_id) => User::find(user_id)
                .await
                .ok()
                .filter(|u| u.check_enabled().is_ok() && u.check_expired().is_ok()),
            None => None,
        };
        let Some(user) = user else {
            device.wrong_pin(attempt, &ip).await?;
            return if attempt >= PIN_MAX_FAILURES {
                Ok(pin_error(StatusCode::LOCKED, "locked", None))
            } else {
                Ok(pin_error(
                    StatusCode::UNAUTHORIZED,
                    "wrong_pin",
                    Some(PIN_MAX_FAILURES - attempt),
                ))
            };
        };
        device.release_attempt(&ip).await?;

        user
    };

    let auth_step = authorize::post_authorize_pin(&req, payload, session, user).await?;
    let mut resp = map_auth_step(auth_step, &req, NewFederatedUserCreated::No).await?;
    // renew the device cookie with each use
    resp.add_cookie(&SharedDevice::build_cookie(&device_token))?;
    Ok(resp)
}

// ##################################################################################
// PINs of the user
// ##################################################################################

/// The practices in which this user may have a PIN
///
/// **Permissions**
/// - authenticated and logged in user for this very {id}
#[utoipa::path(
    get,
    path = "/users/{id}/shared_device_pins",
    tag = "shared_devices",
    responses(
        (status = 200, description = "Ok", body = [SharedDevicePinInfoResponse]),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[get("/users/{id}/shared_device_pins")]
pub async fn get_user_pins(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_session_auth()?;
    let id = path.into_inner();
    principal.is_user(&id)?;

    let pins = SharedDeviceMember::find_for_user(&id)
        .await?
        .into_iter()
        .map(|m| SharedDevicePinInfoResponse {
            practice_id: m.practice_id,
            practice_name: m.practice_name,
            pin_created: m.pin_created,
        })
        .collect::<Vec<_>>();
    Ok(HttpResponse::Ok().json(pins))
}

/// Create a new PIN for the devices of a practice
///
/// The PIN is random, free within the practice, and returned exactly once. A previous PIN stops
/// working, and the user's PIN sessions on the devices of the practice end. Needs a fresh
/// `MfaModToken` from a passkey, which is consumed.
///
/// **Permissions**
/// - authenticated and logged in user for this very {id}
#[utoipa::path(
    post,
    path = "/users/{id}/shared_device_pins/{practice_id}",
    tag = "shared_devices",
    request_body = SharedDevicePinGenerateRequest,
    responses(
        (status = 200, description = "Ok", body = SharedDevicePinResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "NotFound", body = ErrorResponse),
        (status = 429, description = "TooManyRequests", body = ErrorResponse),
    ),
)]
#[post("/users/{id}/shared_device_pins/{practice_id}")]
pub async fn post_user_pin(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    principal: ReqPrincipal,
    Json(payload): Json<SharedDevicePinGenerateRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_session_auth()?;
    payload.validate()?;
    let (id, practice_id) = path.into_inner();
    principal.is_user(&id)?;
    validate_practice_id(&practice_id)?;

    let ip = real_ip_from_req(&req)?;
    let token = MfaModToken::find(&payload.mfa_mod_token_id).await?;
    token.validate(&id, ip)?;
    let user = User::find(id.clone()).await?;
    if !user.has_webauthn_enabled() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "A PIN is only available for accounts with a passkey",
        ));
    }
    if SharedDeviceMember::find(&practice_id, &id).await?.is_none() {
        return Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "Not a member of this practice",
        ));
    }
    SharedDeviceMember::check_generate_limit(&practice_id, &id).await?;
    token.delete().await?;

    let pin = SharedDeviceMember::generate_pin(&practice_id, &id).await?;
    SharedDeviceEvent::create(
        &practice_id,
        None,
        Some(&id),
        SharedDeviceEventKind::PinChanged,
        Some(&ip.to_string()),
    )
    .await?;
    info!(user_id = id, practice_id, "new shared device PIN");

    Ok(no_store(&mut HttpResponse::Ok()).json(SharedDevicePinResponse { pin }))
}

// The application backend performs tenant authorization; these paths additionally require
// the same narrowly scoped API key as existing shared-device administration.
#[derive(serde::Deserialize)]
pub struct RoleSetup {
    user_id: String,
}

#[put("/shared_devices/practices/{id}/roles")]
pub async fn enable_roles(
    path: web::Path<String>,
    principal: ReqPrincipal,
    Json(body): Json<RoleSetup>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Update)?;
    let practice = path.into_inner();
    validate_practice_id(&practice)?;
    SharedDevicePractice::find(&practice).await?;
    let user = User::find(body.user_id).await?;
    user.check_enabled()?;
    if !user.has_webauthn_enabled()
        || SharedDeviceMember::find(&practice, &user.id)
            .await?
            .is_none()
    {
        return Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Practice account requires membership and passkey",
        ));
    }
    PracticeRole::enable(&practice, &user.id).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[get("/shared_devices/practices/{id}/roles")]
pub async fn get_roles(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Read)?;
    let practice = path.into_inner();
    let mut result = Vec::new();
    for role in practice_roles::ROLES {
        let configured = PracticeRole::find(&practice, role).await?;
        result.push(serde_json::json!({"role": role, "enabled": practice_roles::enabled(&practice).await? && configured.is_some(),
            "has_pin": configured.is_some_and(|c| c.pin_hmac.is_some())}));
    }
    Ok(no_store(&mut HttpResponse::Ok()).json(result))
}

// No Debug: neither password nor PIN may be logged.
#[derive(serde::Deserialize)]
pub struct RolePinChange {
    user_id: String,
    pin: String,
    session_id: Option<String>,
    password: Option<String>,
}

#[put("/shared_devices/practices/{id}/roles/{role}/pin")]
pub async fn set_role_pin(
    path: web::Path<(String, String)>,
    principal: ReqPrincipal,
    Json(body): Json<RolePinChange>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Update)?;
    let (practice, role) = path.into_inner();
    let configured = PracticeRole::find(&practice, &role)
        .await?
        .ok_or_else(|| ErrorResponse::new(ErrorResponseType::NotFound, "Role unavailable"))?;
    if configured.user_id != body.user_id {
        return Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Wrong practice account",
        ));
    }
    if let Some(session) = body.session_id {
        let live = practice_roles::live_session(&session).await?;
        if live["practice_id"] != practice
            || live["role"] != role
            || live["user_id"] != body.user_id
        {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "Only the active role can change its PIN",
            ));
        }
    } else {
        let password = body.password.ok_or_else(|| {
            ErrorResponse::new(ErrorResponseType::Forbidden, "Confirm account password")
        })?;
        practice_roles::validate_account_password(&User::find(body.user_id).await?, password)
            .await?;
    }
    configured.set_pin(&body.pin).await?;
    SharedDeviceEvent::create_context(
        &practice,
        None,
        Some(&configured.user_id),
        SharedDeviceEventKind::PinChanged,
        None,
        Some(&role),
    )
    .await?;
    Ok(no_store(&mut HttpResponse::NoContent()).finish())
}

#[get("/shared_devices/sessions/{id}")]
pub async fn get_live_session(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Read)?;
    Ok(no_store(&mut HttpResponse::Ok())
        .json(practice_roles::live_session(&path.into_inner()).await?))
}

#[delete("/shared_devices/practices/{id}/roles")]
pub async fn disable_roles(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal
        .validate_api_key_or_admin_session(AccessGroup::SharedDevices, AccessRights::Update)?;
    practice_roles::disable(&path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}
