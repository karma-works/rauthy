use crate::events::event::Event;
use crate::fido_mds::masks::{AttachmentHintMask, KeyProtectionMask, MdsCertLevel};
use crate::fido_mds::mds_entry::MdsEntrySimple;
use crate::rauthy_config::RauthyConfig;
use actix_web::HttpRequest;
use rauthy_common::utils::real_ip_from_req;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use tracing::{debug, error, info, warn};

pub mod aaguid;
pub mod auth_data;
pub mod auth_req;
pub mod authenticate;
pub mod authenticate_rk;
mod ceremony;
pub mod passkey;
pub mod register;
pub mod rk_token;

/// The pseudonym of a credential ID for logs and events: HMAC-SHA256 with the secret
/// `webauthn.log_cred_hmac_key`, hex, cut to 16 chars. It lets operators follow one passkey
/// through the logs without the ID itself. `None` without a key, so the field is left out.
pub fn cred_log_id(cred_id: &[u8]) -> Option<String> {
    RauthyConfig::get()
        .vars
        .webauthn
        .log_cred_hmac_key
        .as_ref()
        .map(|key| cred_hmac(&key.0, cred_id))
}

/// How the browser found the passkey in a login, for `webauthn.auth.finish`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPath {
    /// No user known upfront, the browser offers its discoverable credentials
    Discoverable,
    /// The user is known from the E-Mail, the browser gets the allowed credentials
    EmailFirst,
    /// A logged-in user confirms an action (MFA mod token, password change, test, ...)
    Service,
}

impl AuthPath {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discoverable => "discoverable",
            Self::EmailFirst => "email_first",
            Self::Service => "service",
        }
    }
}

/// The `result` of a failed `webauthn.auth.finish`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailReason {
    /// The credential is not (or no longer) registered
    UnknownCredential,
    /// The User Handle does not belong to the credential
    UserHandleMismatch,
    /// The session already belongs to another user
    SessionMismatch,
    /// The ceremony state is gone: expired, or the `code` was used already
    StateNotFound,
    /// User Verification required but missing
    UvMissing,
    /// The authenticator does not meet the attestation requirements (anymore)
    Attestation,
    /// The signature or another check of `webauthn-rs` failed
    Verification,
    /// Database or cache error
    Db,
}

impl AuthFailReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownCredential => "unknown_credential",
            Self::UserHandleMismatch => "user_handle_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::StateNotFound => "state_not_found",
            Self::UvMissing => "uv_missing",
            Self::Attestation => "attestation",
            Self::Verification => "verification",
            Self::Db => "db",
        }
    }

    /// Only failures that say something about a passkey or an attack become a
    /// `PasskeyAuthFailed` event. Expired ceremonies and database errors stay in the log.
    fn is_event(&self) -> bool {
        !matches!(self, Self::StateNotFound | Self::Db)
    }
}

/// Writes the `webauthn.auth.finish` log line of a successful passkey login.
pub(crate) fn log_auth_ok(path: AuthPath, cred_id: &[u8], user_id: &str) {
    let cred = cred_log_id(cred_id);
    info!(
        path = path.as_str(),
        result = "ok",
        cred = cred.as_deref(),
        user_id,
        "webauthn.auth.finish"
    );
}

/// Writes the `webauthn.auth.finish` log line of a failed passkey login and, depending on the
/// reason, sends a `PasskeyAuthFailed` event. Neither contains an E-Mail or a passkey name.
pub(crate) async fn log_auth_failed(
    req: &HttpRequest,
    path: Option<AuthPath>,
    reason: AuthFailReason,
    cred_id: Option<&[u8]>,
    user_id: Option<&str>,
) {
    let cred = cred_id.and_then(cred_log_id);
    let path = path.map(|p| p.as_str());
    warn!(
        path,
        result = reason.as_str(),
        cred = cred.as_deref(),
        user_id,
        "webauthn.auth.finish"
    );

    if reason.is_event() {
        let text = format!(
            "{} - path: {}, user: {}, cred: {}",
            reason.as_str(),
            path.unwrap_or("-"),
            user_id.unwrap_or("-"),
            cred.as_deref().unwrap_or("-"),
        );
        let ip = real_ip_from_req(req).ok().map(|ip| ip.to_string());
        if let Err(err) = Event::passkey_auth_failed(text, ip).send().await {
            error!(?err, "Sending the PasskeyAuthFailed event");
        }
    }
}

fn cred_hmac(key: &[u8], cred_id: &[u8]) -> String {
    let mac = hmac_sha256::HMAC::mac(cred_id, key);
    hex::encode(&mac[..8])
}

#[inline]
#[must_use]
pub(crate) fn force_mds_attestation() -> bool {
    let config = &RauthyConfig::get().vars.webauthn;
    config.force_passkey_cert_level.is_some()
        || config.force_passkey_protection.is_some()
        || config.force_passkey_attachment.is_some()
}

async fn verify_attestation(
    aaguid: Option<&[u8]>,
    user_id: &str,
    pk_name: &str,
) -> Result<(), ErrorResponse> {
    if !force_mds_attestation() {
        return Ok(());
    }

    // We handle the AAGUID in a way that whenever this exists, the device was verified during
    // registration. There can never be a situation where an entity has the AAGUID set without
    // being attested.
    let Some(aaguid) = &aaguid else {
        debug!(
            "FIDO attestation enforced but passkey has not been verified: {user_id} / {pk_name}",
        );
        return Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Missing FIDO authenticator attestation",
        ));
    };
    let mds = MdsEntrySimple::find(aaguid).await?;
    let config = &RauthyConfig::get().vars.webauthn;

    verify_mds_attestation(
        &mds,
        &config.force_passkey_cert_level,
        &config.force_passkey_protection,
        &config.force_passkey_attachment,
    )
}

pub(crate) fn verify_mds_attestation(
    mds: &MdsEntrySimple,
    force_passkey_cert_level: &Option<MdsCertLevel>,
    force_passkey_protection: &Option<KeyProtectionMask>,
    force_passkey_attachment: &Option<AttachmentHintMask>,
) -> Result<(), ErrorResponse> {
    debug!("Validating FIDO attestation for {mds}");

    // Note: It's important that we return 406 instead of 403 here. The UI matches on 406 to show
    // proper i18n for the issue. Also, do NOT update the error messages without also updating the
    // ui. It does string matching after the 406 to select the correct message to show.

    if let Some(level) = force_passkey_cert_level
        && &mds.cert_level < level
    {
        debug!(
            "FIDO certification level mismatch. Allowed: {} / Found: {}",
            level, mds.cert_level
        );
        return Err(ErrorResponse::new(
            ErrorResponseType::NotAccepted,
            "FIDO Authenticator certification level too low",
        ));
    }
    // The values reported by the authenticator must be a subset of the allowed ones (see
    // force_passkey_protection in config.toml).
    if let Some(allowed) = force_passkey_protection
        && !mds.key_protection.is_subset_of(*allowed)
    {
        debug!(
            "FIDO key protection mismatch. Allowed: {} / Found: {}",
            allowed, mds.key_protection
        );
        return Err(ErrorResponse::new(
            ErrorResponseType::NotAccepted,
            "FIDO Authenticator key protection not allowed",
        ));
    }
    // Same subset check as above for the attachment hints.
    if let Some(allowed) = force_passkey_attachment
        && !mds.attachment_hint.is_subset_of(*allowed)
    {
        debug!(
            "FIDO key attachment mismatch. Allowed: {} / Found: {}",
            allowed, mds.attachment_hint
        );
        return Err(ErrorResponse::new(
            ErrorResponseType::NotAccepted,
            "FIDO Authenticator attachment hint not allowed",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido_mds::masks::{
        AttachmentHint, AttachmentHintMask, AttestationTypeMask, KeyProtection, KeyProtectionMask,
    };

    #[test]
    fn cred_hmac_is_keyed_and_short() {
        let id = b"credential-id";
        let a = cred_hmac(b"key-1", id);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        // stable for the same key, so one passkey can be followed through the logs
        assert_eq!(a, cred_hmac(b"key-1", id));
        // a different key gives a different pseudonym
        assert_ne!(a, cred_hmac(b"key-2", id));
        assert_ne!(a, cred_hmac(b"key-1", b"other-credential"));
        // never the plain ID
        assert!(!a.contains(&hex::encode(id)[..16]));
        assert_eq!(
            AuthFailReason::UnknownCredential.as_str(),
            "unknown_credential"
        );
        assert!(AuthFailReason::UnknownCredential.is_event());
        assert!(AuthFailReason::UserHandleMismatch.is_event());
        assert!(!AuthFailReason::StateNotFound.is_event());
        assert!(!AuthFailReason::Db.is_event());
        // RFC 4231 test case 2, cut to 8 bytes
        assert_eq!(
            cred_hmac(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e"
        );
    }

    fn mds_entry(
        key_protection: KeyProtectionMask,
        attachment_hint: AttachmentHintMask,
        cert_level: MdsCertLevel,
    ) -> MdsEntrySimple {
        MdsEntrySimple {
            aaguid: vec![0u8; 16],
            description: "test authenticator".to_string(),
            key_protection,
            attachment_hint,
            attestation_types: AttestationTypeMask::default(),
            cert_level,
        }
    }

    fn prot_mask(flags: &[KeyProtection]) -> KeyProtectionMask {
        let mut mask = KeyProtectionMask::default();
        for flag in flags {
            mask = mask.insert(*flag);
        }
        mask
    }

    fn att_mask(flags: &[AttachmentHint]) -> AttachmentHintMask {
        let mut mask = AttachmentHintMask::default();
        for flag in flags {
            mask = mask.insert(*flag);
        }
        mask
    }

    fn assert_forbidden(res: Result<(), ErrorResponse>, message: &str) {
        let err = res.unwrap_err();
        assert_eq!(err.error, ErrorResponseType::NotAccepted);
        assert_eq!(err.message, message);
    }

    #[test]
    fn no_forced_values_passes() {
        // With nothing forced in the config, any entry passes.
        let mds = mds_entry(
            prot_mask(&[KeyProtection::Software]),
            att_mask(&[AttachmentHint::Internal]),
            MdsCertLevel::NotCertified,
        );
        assert_eq!(verify_mds_attestation(&mds, &None, &None, &None), Ok(()));
    }

    #[test]
    fn cert_level_below_minimum_is_rejected() {
        let mds = mds_entry(
            KeyProtectionMask::default(),
            AttachmentHintMask::default(),
            MdsCertLevel::L1Plus,
        );
        assert_forbidden(
            verify_mds_attestation(&mds, &Some(MdsCertLevel::L2), &None, &None),
            "FIDO Authenticator certification level too low",
        );
    }

    #[test]
    fn cert_level_at_or_above_minimum_passes() {
        for level in [MdsCertLevel::L2, MdsCertLevel::L3Plus] {
            let mds = mds_entry(
                KeyProtectionMask::default(),
                AttachmentHintMask::default(),
                level,
            );
            assert_eq!(
                verify_mds_attestation(&mds, &Some(MdsCertLevel::L2), &None, &None),
                Ok(())
            );
        }
    }

    #[test]
    fn key_protection_subset_passes() {
        // The config.toml example: reporting a subset of the allowed values is fine.
        let mds = mds_entry(
            prot_mask(&[KeyProtection::Hardware, KeyProtection::Tee]),
            AttachmentHintMask::default(),
            MdsCertLevel::NotCertified,
        );
        let allowed = prot_mask(&[
            KeyProtection::Hardware,
            KeyProtection::Tee,
            KeyProtection::SecureElement,
        ]);
        assert_eq!(
            verify_mds_attestation(&mds, &None, &Some(allowed), &None),
            Ok(())
        );
    }

    #[test]
    fn key_protection_disallowed_value_is_rejected() {
        // The other half of the config.toml example: one disallowed value fails the check.
        let mds = mds_entry(
            prot_mask(&[KeyProtection::Hardware, KeyProtection::RemoteHandle]),
            AttachmentHintMask::default(),
            MdsCertLevel::NotCertified,
        );
        let allowed = prot_mask(&[
            KeyProtection::Hardware,
            KeyProtection::Tee,
            KeyProtection::SecureElement,
        ]);
        assert_forbidden(
            verify_mds_attestation(&mds, &None, &Some(allowed), &None),
            "FIDO Authenticator key protection not allowed",
        );
    }

    #[test]
    fn key_protection_empty_mask_passes() {
        // An empty mask is a subset of anything.
        let mds = mds_entry(
            KeyProtectionMask::default(),
            AttachmentHintMask::default(),
            MdsCertLevel::NotCertified,
        );
        assert_eq!(
            verify_mds_attestation(
                &mds,
                &None,
                &Some(prot_mask(&[KeyProtection::Hardware])),
                &None
            ),
            Ok(())
        );
    }

    #[test]
    fn key_protection_unknown_flag_is_rejected() {
        // Unrecognized MDS values fold into `Unknown`, which never appears in the config, so
        // the check fails closed.
        let mds = mds_entry(
            prot_mask(&[KeyProtection::Unknown]),
            AttachmentHintMask::default(),
            MdsCertLevel::NotCertified,
        );
        assert_forbidden(
            verify_mds_attestation(
                &mds,
                &None,
                &Some(prot_mask(&[KeyProtection::Hardware])),
                &None,
            ),
            "FIDO Authenticator key protection not allowed",
        );
    }

    #[test]
    fn attachment_hint_subset_passes() {
        let mds = mds_entry(
            KeyProtectionMask::default(),
            att_mask(&[AttachmentHint::External, AttachmentHint::Wired]),
            MdsCertLevel::NotCertified,
        );
        let allowed = att_mask(&[AttachmentHint::External, AttachmentHint::Wired]);
        assert_eq!(
            verify_mds_attestation(&mds, &None, &None, &Some(allowed)),
            Ok(())
        );
    }

    #[test]
    fn attachment_hint_disallowed_value_is_rejected() {
        let mds = mds_entry(
            KeyProtectionMask::default(),
            att_mask(&[AttachmentHint::External, AttachmentHint::Nfc]),
            MdsCertLevel::NotCertified,
        );
        let allowed = att_mask(&[AttachmentHint::External]);
        assert_forbidden(
            verify_mds_attestation(&mds, &None, &None, &Some(allowed)),
            "FIDO Authenticator attachment hint not allowed",
        );
    }

    #[test]
    fn cert_level_check_runs_before_protection_checks() {
        // Both checks fail here; the certification level error is reported first.
        let mds = mds_entry(
            prot_mask(&[KeyProtection::Software]),
            AttachmentHintMask::default(),
            MdsCertLevel::L1Plus,
        );
        assert_forbidden(
            verify_mds_attestation(
                &mds,
                &Some(MdsCertLevel::L2),
                &Some(prot_mask(&[KeyProtection::Hardware])),
                &None,
            ),
            "FIDO Authenticator certification level too low",
        );
    }
}
