//! Authentication of the official FIDO MDS BLOB, including signing-certificate revocation.
//!
//! The pinned GlobalSign R46 trust anchor is published by FIDO. Because it is a public CA, the
//! signer must additionally be a non-CA TLS signing certificate for exactly mds.fidoalliance.org.
//! Only the current official RS256/x5c profile is accepted. Header URLs are never fetched. CRLs
//! are fetched only after chain/signature validation, from the authenticated chain's GlobalSign
//! distribution points, over HTTPS. Unsupported partial/indirect/delta CRLs fail closed.

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::Id;
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{CrlStatus, X509, X509Crl, X509PurposeId, X509StoreContext};
use rauthy_common::constants::RAUTHY_VERSION;
use rauthy_common::utils::{base64_decode, base64_url_no_pad_decode};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::Duration;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

pub const MDS_SOURCE: &str = "https://mds.fidoalliance.org/";
pub const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_CRL_BYTES: usize = 4 * 1024 * 1024;
const ROOT: &[u8] = include_bytes!("../../../../assets/fido_mds/root-r46.pem");
const MAX_CERTS: usize = 5;
const MAX_CERT_BYTES: usize = 16 * 1024;

/// The prepared asset retains its authentication evidence; it is never just unsigned DB rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SignedBlob {
    pub jwt: String,
    pub crls: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    x5c: Vec<String>,
}

pub(super) struct AuthenticatedBlob {
    pub payload: Vec<u8>,
    pub chain: Vec<X509>,
}

pub(super) fn invalid(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorResponseType::BadRequest, message.into())
}

pub(super) fn authenticate(jwt: &str, now: i64) -> Result<AuthenticatedBlob, ErrorResponse> {
    let root = X509::from_pem(ROOT)?;
    authenticate_with_root(jwt, now, &root)
}

fn authenticate_with_root(
    jwt: &str,
    now: i64,
    root: &X509,
) -> Result<AuthenticatedBlob, ErrorResponse> {
    if jwt.len() > MAX_BLOB_BYTES {
        return Err(invalid("FIDO MDS BLOB exceeds the size limit"));
    }
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) || parts[0].len() > 128 * 1024 {
        return Err(invalid("Malformed FIDO MDS compact JWS"));
    }
    let header: Header = serde_json::from_slice(&base64_url_no_pad_decode(parts[0])?)
        .map_err(|_| invalid("Unsupported or malformed FIDO MDS JWS header"))?;
    if header.alg != "RS256" || header.typ.as_deref().is_some_and(|t| t != "JWT") {
        return Err(invalid("Unsupported FIDO MDS JWS algorithm or type"));
    }
    if header.x5c.is_empty() || header.x5c.len() > MAX_CERTS {
        return Err(invalid("Invalid FIDO MDS signing certificate chain length"));
    }
    let mut certificates = Vec::with_capacity(header.x5c.len());
    for encoded in header.x5c {
        if encoded.len() > MAX_CERT_BYTES * 2 {
            return Err(invalid(
                "FIDO MDS signing certificate exceeds the size limit",
            ));
        }
        let der = base64_decode(&encoded)?;
        if der.len() > MAX_CERT_BYTES {
            return Err(invalid(
                "FIDO MDS signing certificate exceeds the size limit",
            ));
        }
        let (remaining, parsed) = X509Certificate::from_der(&der)
            .map_err(|_| invalid("Malformed FIDO MDS signing certificate"))?;
        if !remaining.is_empty() {
            return Err(invalid("Trailing bytes in FIDO MDS signing certificate"));
        }
        parsed
            .extensions_map()
            .map_err(|_| invalid("Duplicate certificate extensions"))?;
        certificates.push(X509::from_der(&der)?);
    }
    let leaf = certificates.remove(0);
    validate_signer(&leaf)?;
    let mut untrusted = Stack::new()?;
    for cert in certificates {
        untrusted.push(cert)?;
    }
    let mut params = X509VerifyParam::new()?;
    params.set_time(now);
    params.set_auth_level(2);
    params.set_purpose(X509PurposeId::SSL_SERVER)?;
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(root.clone())?;
    store.set_flags(X509VerifyFlags::X509_STRICT)?;
    store.set_param(&params)?;
    let mut context = X509StoreContext::new()?;
    let chain = context
        .init(&store.build(), &leaf, &untrusted, |context| {
            if !context.verify_cert()? {
                return Err(openssl::error::ErrorStack::get());
            }
            Ok(context
                .chain()
                .map(|c| c.iter().map(|c| c.to_owned()).collect::<Vec<_>>()))
        })
        .map_err(|_| invalid("Untrusted or expired FIDO MDS signing certificate chain"))?
        .ok_or_else(|| invalid("Missing verified FIDO MDS certificate chain"))?;
    if chain.len() < 2 || chain.len() > MAX_CERTS {
        return Err(invalid("Invalid verified FIDO MDS signing chain"));
    }
    let key = leaf.public_key()?;
    if key.id() != Id::RSA || key.bits() < 2048 {
        return Err(invalid(
            "FIDO MDS RS256 requires an RSA signing key of at least 2048 bits",
        ));
    }
    let signature = base64_url_no_pad_decode(parts[2])?;
    if signature.len() != key.size() {
        return Err(invalid("Invalid FIDO MDS JWS signature length"));
    }
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
    verifier.set_rsa_padding(Padding::PKCS1)?;
    verifier.update(parts[0].as_bytes())?;
    verifier.update(b".")?;
    verifier.update(parts[1].as_bytes())?;
    if !verifier.verify(&signature)? {
        return Err(invalid("Invalid FIDO MDS BLOB signature"));
    }
    Ok(AuthenticatedBlob {
        payload: base64_url_no_pad_decode(parts[1])?,
        chain,
    })
}

fn validate_signer(leaf: &X509) -> Result<(), ErrorResponse> {
    let der = leaf.to_der()?;
    let (_, certificate) = X509Certificate::from_der(&der)
        .map_err(|_| invalid("Malformed FIDO MDS signing certificate"))?;
    if certificate
        .basic_constraints()
        .map_err(|_| invalid("Invalid signing constraints"))?
        .is_none_or(|e| e.value.ca)
        || certificate
            .key_usage()
            .map_err(|_| invalid("Invalid signing key usage"))?
            .is_none_or(|e| !e.value.digital_signature() || e.value.key_cert_sign())
        || certificate
            .extended_key_usage()
            .map_err(|_| invalid("Invalid signing extended usage"))?
            .is_none_or(|e| !e.value.server_auth)
        || certificate
            .subject_alternative_name()
            .map_err(|_| invalid("Invalid signer identity"))?
            .is_none_or(|e| {
                !e.value
                    .general_names
                    .iter()
                    .any(|n| matches!(n, GeneralName::DNSName("mds.fidoalliance.org")))
            })
    {
        return Err(invalid(
            "FIDO MDS signer is not authorized for mds.fidoalliance.org",
        ));
    }
    Ok(())
}

/// No CRL request is allowed until its certificate chain and BLOB signature are authenticated.
pub(super) async fn collect_crls(chain: &[X509]) -> Result<Vec<Vec<u8>>, ErrorResponse> {
    let client = http_client()?;
    let mut crls = Vec::with_capacity(chain.len() - 1);
    for cert in chain.iter().take(chain.len() - 1) {
        let uri = crl_uri(cert)?;
        crls.push(fetch_bounded(&client, &uri, MAX_CRL_BYTES).await?);
    }
    Ok(crls)
}

fn crl_uri(cert: &X509) -> Result<String, ErrorResponse> {
    let der = cert.to_der()?;
    let (_, parsed) =
        X509Certificate::from_der(&der).map_err(|_| invalid("Malformed CRL certificate"))?;
    let mut uris = Vec::new();
    for extension in parsed.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() {
            for point in &points.points {
                if point.reasons.is_some() || point.crl_issuer.is_some() {
                    return Err(invalid("Partial or indirect FIDO MDS CRL is unsupported"));
                }
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            uris.push(*uri);
                        }
                    }
                }
            }
        }
    }
    if uris.len() != 1 {
        return Err(invalid(
            "FIDO MDS certificate must have one full CRL distribution point",
        ));
    }
    let mut url = reqwest::Url::parse(uris[0]).map_err(|_| invalid("Invalid FIDO MDS CRL URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str() != Some("crl.globalsign.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with(".crl")
    {
        return Err(invalid("Unsupported FIDO MDS CRL distribution point"));
    }
    // GlobalSign advertises HTTP CRLs but also serves them over HTTPS.
    url.set_scheme("https")
        .map_err(|_| invalid("Invalid FIDO MDS CRL URL"))?;
    Ok(url.into())
}

pub(super) fn check_crls(chain: &[X509], crls: &[Vec<u8>], now: i64) -> Result<(), ErrorResponse> {
    if crls.len() != chain.len() - 1 {
        return Err(invalid(
            "Missing FIDO MDS signing-chain revocation information",
        ));
    }
    for (pair, bytes) in chain.windows(2).zip(crls) {
        verify_crl(bytes, &pair[0], &pair[1], now)?;
    }
    Ok(())
}

pub(super) fn verification_deadline(
    chain: &[X509],
    crls: &[Vec<u8>],
    next_update: i64,
) -> Result<i64, ErrorResponse> {
    let mut deadline = next_update;
    for cert in chain {
        let der = cert.to_der()?;
        let (_, parsed) = X509Certificate::from_der(&der)
            .map_err(|_| invalid("Malformed signing certificate"))?;
        deadline = deadline.min(parsed.validity().not_after.timestamp());
    }
    for crl in crls {
        let (_, parsed) = CertificateRevocationList::from_der(crl)
            .map_err(|_| invalid("Malformed signing CRL"))?;
        deadline = deadline.min(
            parsed
                .next_update()
                .ok_or_else(|| invalid("FIDO MDS CRL has no expiry"))?
                .timestamp(),
        );
    }
    Ok(deadline)
}

fn verify_crl(bytes: &[u8], cert: &X509, issuer: &X509, now: i64) -> Result<(), ErrorResponse> {
    if bytes.len() > MAX_CRL_BYTES {
        return Err(invalid("FIDO MDS CRL exceeds the size limit"));
    }
    let (remaining, parsed) = CertificateRevocationList::from_der(bytes)
        .map_err(|_| invalid("Malformed FIDO MDS CRL"))?;
    if !remaining.is_empty() {
        return Err(invalid("Trailing bytes in FIDO MDS CRL"));
    }
    if parsed.signature_algorithm.algorithm != parsed.tbs_cert_list.signature.algorithm
        || !matches!(
            parsed.signature_algorithm.algorithm.to_id_string().as_str(),
            "1.2.840.113549.1.1.11" | "1.2.840.113549.1.1.12" | "1.2.840.113549.1.1.13"
        )
    {
        return Err(invalid("Unsupported FIDO MDS CRL signature algorithm"));
    }
    let mut extensions = std::collections::HashSet::new();
    for extension in parsed.extensions() {
        let oid = extension.oid.to_id_string();
        if !extensions.insert(oid.clone())
            || oid == "2.5.29.27"
            || oid == "2.5.29.28"
            || extension.critical
        {
            return Err(invalid(
                "Unsupported critical, duplicate, partial or delta FIDO MDS CRL",
            ));
        }
    }
    for revoked in parsed.iter_revoked_certificates() {
        if revoked
            .extensions()
            .iter()
            .any(|e| e.critical || e.oid.to_id_string() == "2.5.29.29")
        {
            return Err(invalid(
                "Unsupported indirect or critical FIDO MDS CRL entry",
            ));
        }
    }
    let issuer_der = issuer.to_der()?;
    let (_, issuer_parsed) = X509Certificate::from_der(&issuer_der)
        .map_err(|_| invalid("Malformed FIDO MDS CRL issuer"))?;
    if issuer_parsed
        .key_usage()
        .map_err(|_| invalid("Invalid FIDO MDS CRL key usage"))?
        .is_none_or(|e| !e.value.crl_sign())
    {
        return Err(invalid(
            "FIDO MDS CRL issuer is not authorized to sign CRLs",
        ));
    }
    let crl = X509Crl::from_der(bytes)?;
    let issuer_key = issuer.public_key()?;
    if crl.issuer_name().to_der()? != issuer.subject_name().to_der()? || !crl.verify(&issuer_key)? {
        return Err(invalid("Invalid FIDO MDS CRL issuer or signature"));
    }
    let now = Asn1Time::from_unix(now)?;
    if crl.last_update().compare(&now)? == Ordering::Greater
        || crl
            .next_update()
            .is_none_or(|next| next.compare(&now).map_or(true, |o| o != Ordering::Greater))
    {
        return Err(invalid("FIDO MDS CRL is expired or not yet valid"));
    }
    if !matches!(crl.get_by_cert(cert), CrlStatus::NotRevoked) {
        return Err(invalid("FIDO MDS signing certificate has been revoked"));
    }
    Ok(())
}

pub fn http_client() -> Result<reqwest::Client, ErrorResponse> {
    Ok(reqwest::Client::builder()
        .user_agent(format!("Rauthy FIDO MDS/{RAUTHY_VERSION}"))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .build()?)
}

/// Bounded even when Content-Length is missing or false; redirects are deliberately unsupported.
pub async fn fetch_bounded(
    client: &reqwest::Client,
    source: &str,
    max: usize,
) -> Result<Vec<u8>, ErrorResponse> {
    let url = reqwest::Url::parse(source).map_err(|_| invalid("Invalid FIDO MDS source URL"))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(
            "FIDO MDS download requires HTTPS without URL credentials",
        ));
    }
    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(invalid(format!(
            "FIDO MDS download failed: {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(invalid("FIDO MDS download exceeds the size limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > max {
            return Err(invalid("FIDO MDS download exceeds the size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
