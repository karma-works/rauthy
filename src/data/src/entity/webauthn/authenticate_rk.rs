use crate::entity::browser_id::BrowserId;
use crate::entity::login_locations::LoginLocation;
use crate::entity::sessions::{MfaMethod, Session};
use crate::entity::users::User;
use crate::entity::webauthn::auth_data::{WebauthnAdditionalData, WebauthnData};
use crate::entity::webauthn::passkey::{PasskeyEntity, needs_rk_heal};
use crate::entity::webauthn::rk_token::ResidentKeyToken;
use crate::entity::webauthn::{
    AuthFailReason, AuthPath, cred_log_id, log_auth_failed, log_auth_ok, verify_attestation,
};
use crate::rauthy_config::RauthyConfig;
use actix_web::HttpRequest;
use chrono::Utc;
use rauthy_api_types::users::WebauthnAuthStartResponse;
use rauthy_common::utils::get_rand;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::str::FromStr;
use tracing::{error, info};
use webauthn_rs::prelude::{Credential, Uuid};
use webauthn_rs_proto::{PublicKeyCredential, UserVerificationPolicy};

/// Starts the user discovery flow via Resident Keys.
pub async fn auth_start_discover() -> Result<WebauthnAuthStartResponse, ErrorResponse> {
    match RauthyConfig::get()
        .webauthn
        .start_passkey_authentication(&[])
    {
        Ok((mut rcr, auth_state)) => {
            let req_exp = RauthyConfig::get().vars.webauthn.req_exp;
            // timeout expected in ms
            rcr.public_key.timeout = Some(min(req_exp.as_millis(), u32::MAX as u128) as u32);
            rcr.public_key.user_verification = UserVerificationPolicy::Required;

            // cannot be serialized with bincode -> no deserialize from any
            let auth_state_json = serde_json::to_string(&auth_state)?;
            let auth_data = WebauthnData {
                code: get_rand(48),
                auth_state_json,
                data: WebauthnAdditionalData::Discover(None),
            };
            auth_data.save().await?;

            Ok(WebauthnAuthStartResponse {
                code: auth_data.code,
                rcr,
                exp: req_exp.as_secs(),
            })
        }

        Err(err) => {
            error!(?err, "Webauthn challenge authentication");
            Err(ErrorResponse::new(
                ErrorResponseType::Internal,
                "Internal error with Webauthn Challenge Authentication",
            ))
        }
    }
}

// CAUTION:
// The `PasskeyAuthenticationLocal` and `AuthenticationStateLocal` MUST be direct copies of the
// `webauthn-rs` structs. We need these copies for make true resident key lookups possible, since
// the original structs have private fields we need to access to solve a chicken-and-egg problem.
// Sadly, the crate does not expose a way to do a resident-key-based login without attestation and
// without knowing the user upfront.
//
// When `webautn-rs` is updated, make sure that these 2 types are in sync!
#[derive(Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationLocal {
    ast: AuthenticationStateLocal,
}

// We only care about the `credentials` type here. Let the others be handled by `serde`.
#[derive(Debug, Serialize, Deserialize)]
struct AuthenticationStateLocal {
    credentials: Vec<Credential>,
    policy: serde_json::Value,
    challenge: serde_json::Value,
    appid: serde_json::Value,
    allow_backup_eligible_upgrade: serde_json::Value,
}

pub async fn auth_finish_discover(
    req: &HttpRequest,
    browser_id: BrowserId,
    session: Option<Session>,
    pubkey_cred: PublicKeyCredential,
    auth_data: WebauthnData,
) -> Result<WebauthnAdditionalData, ErrorResponse> {
    let Some(mut session) = session else {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Webauthn user discvoery requires a session conext",
        ));
    };

    let path = Some(AuthPath::Discoverable);
    let cred_id = pubkey_cred.get_credential_id();
    let mut pk_entity = match PasskeyEntity::find_rk_by_cred_id(cred_id).await {
        Ok(pk) => pk,
        Err(err) => {
            let reason = if err.error == ErrorResponseType::NotFound {
                AuthFailReason::UnknownCredential
            } else {
                AuthFailReason::Db
            };
            log_auth_failed(req, path, reason, Some(cred_id), None).await;
            return Err(err);
        }
    };
    let cred = Credential::from(pk_entity.get_pk());

    // This step is a bit tricky. We need to allow the credential we just discovered in the
    // auth state. `webauthn-rs` does not provide a way to do a full discovery without knowing the
    // user upfront. It always wants us to provide the list of allowed credentials in the auth start
    // phase. However, we want to discover it. If not, we could stick with the default passkey flow
    // and there would be no advantage from using resident keys in the first place.
    //
    // To solve this issue, since the credentials in the auth state are private, we deserialize into
    // a generic JSON we can manipulate, and then convert to the final type again. This is very
    // cumbersome and a bit wasteful, but it's the only solution for this problem right now.
    //
    // SAFETY
    // Doing so is actually safe. We look up the credential ID which needs to exist in our database
    // already. When the validation was successful, we also get the unique user ID from the
    // resident key, which we can validate against our saved data. We generated this user ID
    // during the registration ceremony. The credential ID is already
    //
    // TODO we should use something faster than JSON after enough testing
    let mut state_local =
        serde_json::from_str::<PasskeyAuthenticationLocal>(&auth_data.auth_state_json)?;
    state_local.ast.credentials.push(cred);
    let json = serde_json::to_string(&state_local)?;
    let auth_state = serde_json::from_str(&json)?;

    let uid = Some(pk_entity.user_id.as_str());
    match RauthyConfig::get()
        .webauthn
        .finish_passkey_authentication(&pubkey_cred, &auth_state)
    {
        Ok(auth_result) => {
            if let Err(err) = verify_attestation(
                pk_entity.aaguid.as_deref(),
                &pk_entity.user_id,
                &pk_entity.name,
            )
            .await
            {
                log_auth_failed(req, path, AuthFailReason::Attestation, Some(cred_id), uid).await;
                return Err(err);
            }

            if RauthyConfig::get().vars.webauthn.force_uv && !auth_result.user_verified() {
                log_auth_failed(req, path, AuthFailReason::UvMissing, Some(cred_id), uid).await;
                return Err(ErrorResponse::new(
                    ErrorResponseType::Forbidden,
                    "User Verification missing",
                ));
            }
            // The User Handle binds the credential to the user. This check must stay, even
            // though the lookup above only uses the credential ID.
            let Some(user_handle) = pubkey_cred.response.user_handle.as_ref() else {
                log_auth_failed(
                    req,
                    path,
                    AuthFailReason::UserHandleMismatch,
                    Some(cred_id),
                    uid,
                )
                .await;
                return Err(ErrorResponse::new(
                    ErrorResponseType::Forbidden,
                    "User Handle missing",
                ));
            };
            let user_uuid = Uuid::from_slice(user_handle.as_ref()).unwrap_or_default();

            let pk_uuid =
                Uuid::from_str(&pk_entity.passkey_user_id).expect("to always be a valid UUID");
            if pk_uuid != user_uuid {
                log_auth_failed(
                    req,
                    path,
                    AuthFailReason::UserHandleMismatch,
                    Some(cred_id),
                    uid,
                )
                .await;
                return Err(ErrorResponse::new(
                    ErrorResponseType::Forbidden,
                    "Invalid User Handle",
                ));
            }

            let mut user = User::find(pk_entity.user_id.clone()).await?;
            if let Some(suid) = &session.user_id
                && suid != &user.id
            {
                log_auth_failed(
                    req,
                    path,
                    AuthFailReason::SessionMismatch,
                    Some(cred_id),
                    uid,
                )
                .await;
                return Err(ErrorResponse::new(
                    ErrorResponseType::Forbidden,
                    "User ID mismatch for session",
                ));
            }

            session
                .set_authenticated_with_mfa(&user, MfaMethod::WebAuthn)
                .await?;
            user.last_login = Some(Utc::now().timestamp());
            user.last_failed_login = None;
            user.failed_login_attempts = None;
            user.save(None).await?;

            LoginLocation::spawn_background_check(user.clone(), req, browser_id.clone())?;

            // The browser just offered this credential without an allow list, so it is
            // discoverable, whatever the registration reported.
            if needs_rk_heal(pk_entity.resident_key) {
                let before = pk_entity.resident_key;
                match pk_entity.set_resident_key().await {
                    Ok(()) => info!(
                        user_id = user.id,
                        cred = cred_log_id(cred_id).as_deref(),
                        resident_key_before = ?before,
                        "webauthn.rk.healed"
                    ),
                    // The login itself was fine, and the next one tries again.
                    Err(err) => error!(?err, user_id = user.id, "webauthn.rk.heal failed"),
                }
            }

            if auth_result.needs_update() {
                let now = Utc::now().timestamp();
                let mut pk = pk_entity.get_pk();
                if pk.update_credential(&auth_result) == Some(true) {
                    pk_entity.passkey = serde_json::to_string(&pk)?;
                    pk_entity.last_used = now;
                    pk_entity.update_passkey().await?;
                }
            }

            log_auth_ok(AuthPath::Discoverable, cred_id, &user.id);

            let token = ResidentKeyToken::new(session.id, browser_id).await?;
            Ok(WebauthnAdditionalData::Discover(Some(token.code)))
        }
        Err(err) => {
            error!(?err, "Webauthn Auth Finish");
            log_auth_failed(req, path, AuthFailReason::Verification, Some(cred_id), uid).await;
            Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                err.to_string(),
            ))
        }
    }
}
