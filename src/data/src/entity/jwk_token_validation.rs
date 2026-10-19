use crate::entity::jwk::{JWKSPublicKey, JwkKeyPairAlg};
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use rauthy_common::utils::base64_url_no_pad_decode_buf;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use tracing::warn;

impl JWKSPublicKey {
    pub fn validate_token_signature(
        &self,
        token: &str,
        buf: &mut Vec<u8>,
    ) -> Result<(), ErrorResponse> {
        let (message, sig) = token
            .rsplit_once('.')
            .ok_or_else(|| ErrorResponse::new(ErrorResponseType::BadRequest, "Malformed token"))?;

        buf.clear();
        base64_url_no_pad_decode_buf(sig, buf)?;

        match self.alg()? {
            JwkKeyPairAlg::RS256 | JwkKeyPairAlg::RS384 | JwkKeyPairAlg::RS512 => {
                let key = self.rsa_public_key()?;
                let mut verifier = Verifier::new(self.alg()?.rsa_digest()?, &key)?;
                verifier.set_rsa_padding(Padding::PKCS1)?;
                verifier.update(message.as_bytes())?;
                if verifier.verify(buf).unwrap_or(false) {
                    return Ok(());
                }
            }

            JwkKeyPairAlg::EdDSA | JwkKeyPairAlg::Ed25519 => {
                let x = self.x()?;
                let pubkey = ed25519_compact::PublicKey::from_slice(x.as_slice())?;
                let signature = ed25519_compact::Signature::from_slice(buf)?;
                if pubkey.verify(message, &signature).is_ok() {
                    return Ok(());
                }
            }
        };

        warn!("JWT Token validation error");
        Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Invalid JWT Token signature",
        ))
    }
}
