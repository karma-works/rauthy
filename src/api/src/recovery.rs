//! Recovery codes for passkey accounts, see `rauthy_data::entity::recovery_codes`.
//! Everything returns `404` unless `webauthn.recovery_codes` is enabled.

use crate::ReqPrincipal;
use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::web::Json;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, web};
use chrono::Utc;
use rauthy_api_types::users::{
    RecoverStartRequest, RecoverStartResponse, RecoverVerifyRequest, RecoverVerifyResponse,
    RecoveryCodesGenerateRequest, RecoveryCodesInfoResponse, RecoveryCodesResponse,
};
use rauthy_common::constants::PWD_RESET_COOKIE;
use rauthy_common::utils::{get_rand, real_ip_from_req};
use rauthy_data::api_cookie::ApiCookie;
use rauthy_data::email::notification::{
    send_email_recovery_codes_regenerated, send_email_recovery_failures,
    send_email_recovery_mail_code,
};
use rauthy_data::entity::api_keys::{AccessGroup, AccessRights};
use rauthy_data::entity::magic_links::{MagicLink, MagicLinkUsage};
use rauthy_data::entity::mfa_mod_token::MfaModToken;
use rauthy_data::entity::pow::PowEntity;
use rauthy_data::entity::recovery_codes::{
    MAIL_CODE_LIFETIME_SECS, RecoveryChallenge, RecoveryCodes, RecoveryLock,
};
use rauthy_data::entity::users::User;
use rauthy_data::events::event::Event;
use rauthy_data::rauthy_config::RauthyConfig;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use spow::pow::Pow;
use std::time::Duration;
use tokio::time::{Instant, sleep_until};
use tracing::{error, info, warn};
use validator::Validate;

/// `POST /users/recover/start` always takes at least this long, so that the response time does not
/// reveal whether an account exists, a code was valid or redeeming is locked.
const RECOVER_START_MIN_DURATION: Duration = Duration::from_millis(1500);
/// The link that allows to register a passkey after a successful recovery
const RECOVERY_LINK_LIFETIME: Duration = Duration::from_secs(600);

fn check_enabled() -> Result<(), ErrorResponse> {
    if RauthyConfig::get().vars.webauthn.recovery_codes {
        Ok(())
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "Recovery codes are not enabled",
        ))
    }
}

fn no_store(resp: &mut actix_web::HttpResponseBuilder) -> &mut actix_web::HttpResponseBuilder {
    resp.insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((PRAGMA, "no-cache"))
}

/// Creates new recovery codes for this user
///
/// All existing codes become invalid. The codes are returned exactly once. Needs a fresh
/// `MfaModToken`, which is consumed. Only for accounts with a passkey.
///
/// **Permissions**
/// - authenticated and logged in user for this very {id}
#[utoipa::path(
    post,
    path = "/users/{id}/recovery_codes",
    tag = "mfa",
    request_body = RecoveryCodesGenerateRequest,
    responses(
        (status = 200, description = "Ok", body = RecoveryCodesResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 429, description = "TooManyRequests", body = ErrorResponse),
    ),
)]
#[post("/users/{id}/recovery_codes")]
pub async fn post_recovery_codes(
    path: web::Path<String>,
    principal: ReqPrincipal,
    req: HttpRequest,
    Json(payload): Json<RecoveryCodesGenerateRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_session_auth()?;
    payload.validate()?;
    let id = path.into_inner();
    principal.is_user(&id)?;

    let ip = real_ip_from_req(&req)?;
    let token = MfaModToken::find(&payload.mfa_mod_token_id).await?;
    token.validate(&id, ip)?;

    let user = User::find(id.clone()).await?;
    // A password or OTP must never be enough to create codes that bypass the passkey.
    if !user.has_webauthn_enabled() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Recovery codes are only available for accounts with a passkey",
        ));
    }
    RecoveryCodes::check_generate_limit(&id).await?;
    token.delete().await?;

    let codes = RecoveryCodes::generate(&id).await?;
    // a new set also ends a recovery that is just in progress
    RecoveryChallenge::cancel_for_user(&id).await?;
    MagicLink::delete_recovery_links_for_user(&id).await?;

    info!(user.id, "New recovery codes created");
    Event::recovery_codes_regenerated(user.email.clone(), Some(ip.to_string()))
        .send()
        .await?;
    send_email_recovery_codes_regenerated(&user).await;

    Ok(
        no_store(&mut HttpResponse::Ok()).json(RecoveryCodesResponse {
            recovery_codes: codes,
        }),
    )
}

/// How many unused recovery codes a user has
///
/// **Permissions**
/// - authenticated and logged in user for this very {id}
/// - rauthy_admin, a group admin for a user it manages, or an API key with Users + Read
#[utoipa::path(
    get,
    path = "/users/{id}/recovery_codes",
    tag = "mfa",
    responses(
        (status = 200, description = "Ok", body = RecoveryCodesInfoResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[get("/users/{id}/recovery_codes")]
pub async fn get_recovery_codes(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    let id = path.into_inner();
    if principal.is_user(&id).is_ok() {
        principal.validate_session_auth()?;
    } else {
        principal.validate_api_key_or_group_admin(AccessGroup::Users, AccessRights::Read)?;
        let user = User::find(id.clone()).await?;
        principal.validate_group_admin_can_manage(user.roles_iter(), user.groups_iter())?;
    }

    let info = RecoveryCodes::info(&id).await?;
    Ok(HttpResponse::Ok().json(RecoveryCodesInfoResponse {
        remaining: info.remaining,
        created: info.created,
    }))
}

/// Deletes all recovery codes of a user and unlocks redeeming
///
/// **Permissions**
/// - rauthy_admin, a group admin for a user it manages, or an API key with Users + Delete
#[utoipa::path(
    delete,
    path = "/users/{id}/recovery_codes",
    tag = "mfa",
    responses(
        (status = 200, description = "Ok"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
#[delete("/users/{id}/recovery_codes")]
pub async fn delete_recovery_codes(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    principal.validate_api_key_or_group_admin(AccessGroup::Users, AccessRights::Delete)?;
    let user = User::find(path.into_inner()).await?;
    principal.validate_group_admin_can_manage(user.roles_iter(), user.groups_iter())?;

    purge_for_user(&user).await?;
    warn!(user.id, "Recovery codes deleted by an admin");

    Ok(HttpResponse::Ok().finish())
}

/// Removes codes, a recovery in progress and the lock, e.g. when an admin resets passkeys.
pub async fn purge_for_user(user: &User) -> Result<(), ErrorResponse> {
    RecoveryCodes::delete_for_user(&user.id).await?;
    RecoveryChallenge::cancel_for_user(&user.id).await?;
    MagicLink::delete_recovery_links_for_user(&user.id).await?;
    RecoveryLock::clear(&user.email).await?;
    Ok(())
}

/// Redeems a recovery code
///
/// Always returns the same response, no matter if the account exists, the code is valid or the
/// IP is blocked after too many failures, and always takes the same time. If the code is valid, a confirmation code
/// is sent to the account's E-Mail, see `POST /users/recover/verify`.
#[utoipa::path(
    post,
    path = "/users/recover/start",
    tag = "mfa",
    request_body = RecoverStartRequest,
    responses(
        (status = 200, description = "Ok", body = RecoverStartResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
    ),
)]
#[post("/users/recover/start")]
pub async fn post_recover_start(
    req: HttpRequest,
    Json(payload): Json<RecoverStartRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    let deadline = Instant::now() + RECOVER_START_MIN_DURATION;
    payload.validate()?;
    let challenge = Pow::validate(&payload.pow)?;
    PowEntity::check_prevent_reuse(challenge.to_string()).await?;
    let ip = real_ip_from_req(&req)?.to_string();

    let res = RecoveryChallenge::start(&payload.email, &payload.code, &ip).await;
    let resp = match res {
        Ok(start) => {
            // Mails and events run in the background: a slow mail queue must not make the
            // response of existing accounts take longer.
            if let Some((user, mail_code)) = start.mail {
                info!(
                    user.id,
                    "Recovery code redeemed, sending the confirmation code"
                );
                tokio::spawn(async move {
                    send_email_recovery_mail_code(&user, &mail_code, MAIL_CODE_LIFETIME_SECS / 60)
                        .await;
                });
            }
            if let Some(user) = start.warn_user {
                warn!(user.id, "Repeated invalid recovery codes for an account");
                let ip = ip.clone();
                tokio::spawn(async move {
                    if let Err(err) = Event::recovery_code_failed(user.email.clone(), Some(ip))
                        .send()
                        .await
                    {
                        error!(?err, "Sending the RecoveryCodeFailed event");
                    }
                    send_email_recovery_failures(&user).await;
                });
            }
            Ok(
                no_store(&mut HttpResponse::Ok()).json(RecoverStartResponse {
                    challenge_id: start.challenge.id,
                    exp: start.challenge.exp,
                }),
            )
        }
        Err(err) => Err(err),
    };

    sleep_until(deadline).await;
    resp
}

/// Confirms a recovery with the code from the E-Mail
///
/// On success, the response allows to register a new passkey in this browser with
/// `POST /users/{user_id}/webauthn/register/start|finish`, `magic_link_id` and the
/// `x-pwd-csrf-token` header. It sets the binding cookie for this. Afterwards, all sessions of the
/// user are ended.
#[utoipa::path(
    post,
    path = "/users/recover/verify",
    tag = "mfa",
    request_body = RecoverVerifyRequest,
    responses(
        (status = 200, description = "Ok", body = RecoverVerifyResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
    ),
)]
#[post("/users/recover/verify")]
pub async fn post_recover_verify(
    Json(payload): Json<RecoverVerifyRequest>,
) -> Result<HttpResponse, ErrorResponse> {
    check_enabled()?;
    payload.validate()?;

    let user_id = RecoveryChallenge::verify(&payload.challenge_id, &payload.mail_code).await?;

    // only one recovery link at a time
    MagicLink::delete_recovery_links_for_user(&user_id).await?;
    let mut ml = MagicLink::create(
        user_id.clone(),
        RECOVERY_LINK_LIFETIME,
        MagicLinkUsage::PasskeyRecovery,
    )
    .await?;
    ml.cookie = Some(get_rand(48));
    ml.save().await?;

    let max_age = ml.exp - Utc::now().timestamp();
    let cookie = ApiCookie::build(PWD_RESET_COOKIE, ml.cookie.clone().unwrap(), max_age);

    Ok(no_store(&mut HttpResponse::Ok())
        .cookie(cookie)
        .json(RecoverVerifyResponse {
            user_id,
            magic_link_id: ml.id,
            csrf_token: ml.csrf_token,
        }))
}
