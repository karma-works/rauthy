use crate::database::{Cache, DB};
use crate::email::notification::send_email_passkey_added;
use crate::entity::users::User;
use crate::entity::webauthn::aaguid::attested_aaguid;
use crate::entity::webauthn::ceremony::{RegistrationState, requires_uv};
use crate::entity::webauthn::passkey::PasskeyEntity;
use crate::entity::webauthn::{cred_log_id, force_mds_attestation, verify_attestation};
use crate::events::event::Event;
use crate::fido_mds::authenticator::MdsAuthenticator;
use crate::rauthy_config::RauthyConfig;
use rauthy_api_types::users::{
    AuthenticatorAttachment, PasskeyHint, PasskeyKind, WebauthnRegFinishRequest,
    WebauthnRegStartRequest,
};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::str::FromStr;
use tracing::{error, info, warn};
use webauthn_rs::prelude::{Credential, Uuid, WebauthnError};
use webauthn_rs_proto::{
    AuthenticatorTransport, CreationChallengeResponse, ExtnState, PublicKeyCredentialHints,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebauthnReg {
    pub user_id: String,
    pub passkey_user_id: Uuid,
    pub reg_state: String,
}

pub async fn reg_start(
    user_id: String,
    payload: WebauthnRegStartRequest,
    ctx: RegContext,
) -> Result<CreationChallengeResponse, ErrorResponse> {
    let user = User::find(user_id).await?;
    let passkey_user_id = if let Some(id) = &user.webauthn_user_id {
        Uuid::from_str(id).expect("corrupted database: user.webauthn_user_id")
    } else {
        Uuid::new_v4()
    };
    let exclude_creds = {
        let pks = PasskeyEntity::find_cred_ids_for_user(&user.id).await?;
        if !pks.is_empty() { Some(pks) } else { None }
    };

    let cfg = &RauthyConfig::get().vars.webauthn;
    let allow_rk = payload.allow_rk.unwrap_or(false);
    if !cfg.is_passkey_reg_type_allowed(allow_rk) {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "This Passkey Type is not allowed",
        ));
    }
    // New-user magic links may remove an initialized password at finish.
    let require_uv =
        requires_uv(user.account_type(), cfg.force_uv) || payload.magic_link_id.is_some();

    info!(
        user_id = user.id,
        path = ctx.as_str(),
        rk_requested = allow_rk,
        uv_required = require_uv,
        "webauthn.reg.start"
    );

    let attestation_ca_list = if cfg.optimistic_attestation || force_mds_attestation() {
        MdsAuthenticator::get_ca_list().await?
    } else {
        None
    };

    match RegistrationState::start(
        &RauthyConfig::get().webauthn,
        passkey_user_id,
        &user.email,
        exclude_creds,
        require_uv,
        allow_rk,
        attestation_ca_list,
    ) {
        Ok((mut ccr, reg_state)) => {
            // timeout expected in ms
            ccr.public_key.timeout = Some(min(cfg.req_exp.as_millis(), u32::MAX as u128) as u32);
            if let Some(hints) = &payload.hints
                && !hints.is_empty()
            {
                ccr.public_key.hints = Some(hints.iter().map(|h| webauthn_hint(*h)).collect());
            }

            let cache_idx = format!("reg_{:?}_{}", payload.passkey_name, user.id);
            let reg_data = WebauthnReg {
                user_id: user.id,
                passkey_user_id,
                // the reg_state cannot be serialized with bincode -> missing deserialize from Any
                reg_state: serde_json::to_string(&reg_state)?,
            };
            DB::hql()
                .put(
                    Cache::Webauthn,
                    cache_idx,
                    &reg_data,
                    Some(cfg.req_exp.as_secs() as i64),
                )
                .await?;

            Ok(ccr)
        }

        Err(err) => {
            error!(?err, "Webauthn challenge register");
            Err(ErrorResponse::new(
                ErrorResponseType::Internal,
                "Internal error with Webauthn Challenge Registration",
            ))
        }
    }
}

/// Where a registration comes from
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegContext {
    /// A logged-in user with a fresh `MfaModToken`
    Session,
    /// The `new_user` magic link of the account setup
    NewUser,
    /// A `passkey_recovery` magic link after a redeemed recovery code
    Recovery,
}

impl RegContext {
    /// The `path` in the `webauthn.reg.*` logs. Admins cannot register a passkey for a user.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Session => "account",
            Self::NewUser => "setup",
            Self::Recovery => "recovery",
        }
    }
}

/// Writes the `webauthn.reg.finish` log line of a failed registration.
fn log_reg_failed(user_id: &str, ctx: RegContext, result: &'static str) {
    warn!(user_id, path = ctx.as_str(), result, "webauthn.reg.finish");
}

pub async fn reg_finish(
    id: String,
    payload: WebauthnRegFinishRequest,
    ctx: RegContext,
) -> Result<(), ErrorResponse> {
    let is_new_user = ctx == RegContext::NewUser;
    // a passkey from a magic link must always be user verified
    let force_uv = ctx != RegContext::Session;
    let mut user = User::find(id).await?;

    let idx = format!("reg_{:?}_{}", payload.passkey_name, user.id);
    let reg_data = match DB::hql()
        .get_remove::<_, _, WebauthnReg>(Cache::Webauthn, idx)
        .await?
    {
        None => {
            log_reg_failed(&user.id, ctx, "state_not_found");
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Webauthn Registration Request not found",
            ));
        }
        Some(data) => data,
    };

    let cfg = &RauthyConfig::get().vars.webauthn;
    let reg_state = serde_json::from_str::<RegistrationState>(&reg_data.reg_state)?;
    let mut with_attestation = matches!(
        reg_state,
        RegistrationState::AttestedPasskey(_) | RegistrationState::AttestedSecurityKey(_)
    );

    let res = if cfg.optimistic_attestation && with_attestation {
        match reg_state.finish(&RauthyConfig::get().webauthn, &payload.data) {
            Ok(pk) => Ok(pk),
            Err(err) => {
                if is_attestation_error(&err) {
                    warn!("Error during optimistic FIDO attestation: {err:?}");
                    with_attestation = false;
                    reg_state
                        .into_plain_fallback()
                        .finish(&RauthyConfig::get().webauthn, &payload.data)
                } else {
                    // in case of any non-attestation error, simply forward it
                    Err(err)
                }
            }
        }
    } else {
        reg_state.finish(&RauthyConfig::get().webauthn, &payload.data)
    };

    match res {
        Ok(pk) => {
            let cred = Credential::from(pk.clone());

            if (requires_uv(user.account_type(), cfg.force_uv) || force_uv) && !cred.user_verified {
                log_reg_failed(&user.id, ctx, "uv_missing");
                return Err(ErrorResponse::new(
                    ErrorResponseType::Forbidden,
                    "User Presence only is not allowed - Verification is needed",
                ));
            }

            // webauthn-rs does not expose the AAGUID for all attestation formats, so we read
            // it from the raw attestation object ourselves. A stored AAGUID must always mean
            // "attested device", so this is a deliberate safety net.
            let aaguid = if with_attestation {
                let aaguid = attested_aaguid(
                    &cred.attestation.data,
                    &payload.data.response.attestation_object,
                )?;
                // We should deny the registration when the currently set requirements for attestation
                // are not met.
                if let Some(aaguid) = aaguid {
                    match verify_attestation(
                        Some(aaguid.as_slice()),
                        &user.id,
                        &payload.passkey_name,
                    )
                    .await
                    {
                        Ok(_) => Some(aaguid),
                        Err(err) => {
                            warn!("Cannot verify FIDO device attestation: {}", err.message);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if aaguid.is_none() && force_mds_attestation() {
                log_reg_failed(&user.id, ctx, "attestation");
                // Do NOT update this error message. If you need to, also update the check
                // in the acc dashboard -> frontend/src/lib/account/AccMFA.svelte
                // It grabs the `Missing attestation` from it.
                return Err(ErrorResponse::new(
                    ErrorResponseType::NotAccepted,
                    "The authenticator does not meet the security standards. Missing attestation.",
                ));
            }

            let user_id = user.id.clone();
            // `user` is moved below for the very first passkey
            let notify_user = cfg.notify_passkey_added.then(|| user.clone());
            let passkey_name = payload.passkey_name.clone();
            let kind = passkey_kind(
                payload.authenticator_attachment,
                payload.data.response.transports.as_deref(),
            );
            let create_user = if user.webauthn_user_id.is_none() {
                user.webauthn_user_id = Some(reg_data.passkey_user_id.to_string());

                // We need to check if the user is a possibly manually initialized one, and we
                // need to reset a password. This can happen when an admin adds a user, does a
                // manual init to prevent auto-removal, and then the initial password reset link
                // is used to add a passkey instead. In such a situation, the user would have a
                // random password but never logged in even once, and the Magic Link Usage is
                // NewUser.
                if is_new_user && user.password.is_some() && user.last_login.is_none() {
                    info!(
                        "Resetting manually initialized password for user {}",
                        user.email
                    );
                    user.password = None;
                    user.save(None).await?;
                }

                if user.password.is_none() || cfg.no_password_exp {
                    user.password_expires = None;
                }
                Some(user)
            } else {
                None
            };

            let is_rk = {
                match cred.extensions.cred_props {
                    ExtnState::NotRequested | ExtnState::Ignored => None,
                    ExtnState::Set(props) => props.rk,
                    ExtnState::Unsolicited(props) => props.rk,
                    ExtnState::Unsigned(props) => props.rk,
                }
            };

            let cred_log = cred_log_id(cred.cred_id.as_ref());
            let aaguid_log = aaguid.as_ref().map(hex::encode);
            let kind_log = kind.as_ref().map(|k| k.as_str());
            if let Err(err) = PasskeyEntity::create(
                user_id.clone(),
                create_user,
                reg_data.passkey_user_id,
                payload.passkey_name,
                pk,
                cred.user_verified,
                is_rk,
                aaguid.map(|a| a.to_vec()),
                kind,
            )
            .await
            {
                log_reg_failed(&user_id, ctx, "db");
                return Err(err);
            }

            info!(
                user_id,
                path = ctx.as_str(),
                result = "ok",
                cred = cred_log.as_deref(),
                rk = ?is_rk,
                kind = kind_log,
                aaguid = aaguid_log.as_deref(),
                "webauthn.reg.finish"
            );
            let text = format!(
                "user: {user_id}, path: {}, cred: {}",
                ctx.as_str(),
                cred_log.as_deref().unwrap_or("-"),
            );
            if let Err(err) = Event::passkey_added(text, None).send().await {
                error!(?err, "Sending the PasskeyAdded event");
            }

            if let Some(user) = notify_user {
                send_email_passkey_added(&user, &passkey_name).await;
            }
        }
        Err(err) => {
            error!(?err, "Webauthn Reg Finish");
            let result = if is_attestation_error(&err) {
                "attestation"
            } else {
                "verification"
            };
            log_reg_failed(&user.id, ctx, result);
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!("{err}"),
            ));
        }
    };

    Ok(())
}

fn webauthn_hint(hint: PasskeyHint) -> PublicKeyCredentialHints {
    match hint {
        PasskeyHint::ClientDevice => PublicKeyCredentialHints::ClientDevice,
        PasskeyHint::Hybrid => PublicKeyCredentialHints::Hybrid,
        PasskeyHint::SecurityKey => PublicKeyCredentialHints::SecurityKey,
    }
}

/// Derives how a passkey has been added. Both inputs are reported by the browser, so the result
/// is only meant for display. `None` if the browser reported nothing usable.
fn passkey_kind(
    attachment: Option<AuthenticatorAttachment>,
    transports: Option<&[AuthenticatorTransport]>,
) -> Option<PasskeyKind> {
    if attachment == Some(AuthenticatorAttachment::Platform) {
        return Some(PasskeyKind::Internal);
    }

    let transports = transports.unwrap_or_default();
    let has = |t: AuthenticatorTransport| transports.contains(&t);
    if has(AuthenticatorTransport::Hybrid) {
        // phones report `hybrid` (often together with `internal`)
        Some(PasskeyKind::Hybrid)
    } else if has(AuthenticatorTransport::Usb)
        || has(AuthenticatorTransport::Nfc)
        || has(AuthenticatorTransport::Ble)
    {
        Some(PasskeyKind::SecurityKey)
    } else if has(AuthenticatorTransport::Internal) {
        Some(PasskeyKind::Internal)
    } else {
        None
    }
}

fn is_attestation_error(err: &WebauthnError) -> bool {
    matches!(
        err,
        WebauthnError::MissingAttestationCredentialData
            | WebauthnError::AttestationNotSupported
            | WebauthnError::AttestationStatementMapInvalid
            | WebauthnError::AttestationStatementResponseMissing
            | WebauthnError::AttestationStatementResponseInvalid
            | WebauthnError::AttestationStatementSigMissing
            | WebauthnError::AttestationStatementSigInvalid
            | WebauthnError::AttestationStatementVerMissing
            | WebauthnError::AttestationStatementVerInvalid
            | WebauthnError::AttestationStatementVerUnsupported
            | WebauthnError::AttestationStatementX5CMissing
            | WebauthnError::AttestationStatementX5CInvalid
            | WebauthnError::AttestationStatementAlgMissing
            | WebauthnError::AttestationStatementCertInfoMissing
            | WebauthnError::AttestationStatementMissingExtension
            | WebauthnError::AttestationStatementPubAreaMissing
            | WebauthnError::AttestationStatementAlgMismatch
            | WebauthnError::AttestationStatementAlgInvalid
            | WebauthnError::AttestationTrustFailure
            | WebauthnError::AttestationCertificateAAGUIDMismatch
            | WebauthnError::AttestationCertificateNonceMismatch
            | WebauthnError::AttestationTpmStInvalid
            | WebauthnError::AttestationTpmPubAreaMismatch
            | WebauthnError::AttestationTpmExtraDataInvalid
            | WebauthnError::AttestationTpmExtraDataMismatch
            | WebauthnError::AttestationTpmPubAreaHashUnknown
            | WebauthnError::AttestationTpmPubAreaHashInvalid
            | WebauthnError::AttestationTpmAttestCertifyInvalid
            | WebauthnError::AttestationCertificateRequirementsNotMet
            | WebauthnError::AttestationCertificateTrustStoreEmpty
            | WebauthnError::AttestationLeafCertMissing
            | WebauthnError::AttestationNotVerifiable
            | WebauthnError::AttestationUntrustedAaguid
            | WebauthnError::AttestationFormatMissingAaguid
            | WebauthnError::AttestationChainNotTrusted(_)
            | WebauthnError::AttestationCredentialSubjectKeyMismatch
            | WebauthnError::MissingAttestationCaList
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuthenticatorTransport::{Ble, Hybrid, Internal, Nfc, Usb};

    #[test]
    fn test_passkey_kind() {
        let platform = Some(AuthenticatorAttachment::Platform);
        let cross = Some(AuthenticatorAttachment::CrossPlatform);

        // Windows Hello, Touch ID, iCloud Keychain on this device
        assert_eq!(
            passkey_kind(platform, Some(&[Hybrid, Internal])),
            Some(PasskeyKind::Internal)
        );
        assert_eq!(passkey_kind(platform, None), Some(PasskeyKind::Internal));
        // a smartphone via QR code
        assert_eq!(
            passkey_kind(cross, Some(&[Hybrid, Internal])),
            Some(PasskeyKind::Hybrid)
        );
        // security keys
        assert_eq!(
            passkey_kind(cross, Some(&[Nfc, Usb])),
            Some(PasskeyKind::SecurityKey)
        );
        assert_eq!(
            passkey_kind(None, Some(&[Ble])),
            Some(PasskeyKind::SecurityKey)
        );
        // without attachment, only `internal`
        assert_eq!(
            passkey_kind(None, Some(&[Internal])),
            Some(PasskeyKind::Internal)
        );
        // nothing usable
        assert_eq!(passkey_kind(cross, None), None);
        assert_eq!(passkey_kind(None, Some(&[])), None);
    }

    #[test]
    fn test_webauthn_hint() {
        assert_eq!(
            webauthn_hint(PasskeyHint::Hybrid),
            PublicKeyCredentialHints::Hybrid
        );
        assert_eq!(
            webauthn_hint(PasskeyHint::SecurityKey),
            PublicKeyCredentialHints::SecurityKey
        );
        assert_eq!(
            webauthn_hint(PasskeyHint::ClientDevice),
            PublicKeyCredentialHints::ClientDevice
        );
    }
}
