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
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    x5c: Vec<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
    #[serde(default)]
    b64: Option<bool>,
    #[serde(default)]
    x5u: Option<serde_json::Value>,
    #[serde(default)]
    jku: Option<serde_json::Value>,
    #[serde(default)]
    jwk: Option<serde_json::Value>,
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
    let parts: Vec<&str> = jwt.splitn(4, '.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) || parts[0].len() > 128 * 1024 {
        return Err(invalid("Malformed FIDO MDS compact JWS"));
    }
    let header: Header = serde_json::from_slice(&base64_url_no_pad_decode(parts[0])?)
        .map_err(|_| invalid("Unsupported or malformed FIDO MDS JWS header"))?;
    // Ignore noncritical extensions (for example kid), without letting them select keys or URLs.
    if header.alg != "RS256"
        || header.typ.as_deref().is_some_and(|t| t != "JWT")
        || header.crit.is_some()
        || header.b64 == Some(false)
        || header.x5u.is_some()
        || header.jku.is_some()
        || header.jwk.is_some()
    {
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
) -> Result<i64, ErrorResponse> {
    // nextUpdate schedules a metadata refresh; it is not a certificate/CRL expiry.
    let mut deadline = i64::MAX;
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

/// Only for evidence embedded in a trusted release binary, never for network ingestion.
/// Recover a time at which all bundled certificates and CRLs could have been valid, then let
/// the normal chain, signature and CRL checks authenticate those issuer-signed timestamps.
pub(super) fn embedded_verification_time(signed: &SignedBlob) -> Result<i64, ErrorResponse> {
    if signed.jwt.len() > MAX_BLOB_BYTES || signed.crls.len() >= MAX_CERTS {
        return Err(invalid("Oversized embedded FIDO MDS evidence"));
    }
    let encoded = signed.jwt.split('.').next().unwrap_or_default();
    if encoded.len() > 128 * 1024 {
        return Err(invalid("Oversized embedded FIDO MDS header"));
    }
    let header: Header = serde_json::from_slice(&base64_url_no_pad_decode(encoded)?)
        .map_err(|_| invalid("Malformed embedded FIDO MDS header"))?;
    if header.x5c.is_empty() || header.x5c.len() > MAX_CERTS || signed.crls.is_empty() {
        return Err(invalid("Missing embedded FIDO MDS evidence"));
    }
    let mut at = 0;
    for encoded in header.x5c {
        if encoded.len() > MAX_CERT_BYTES * 2 {
            return Err(invalid("Oversized embedded signing certificate"));
        }
        let der = base64_decode(&encoded)?;
        let (_, cert) = X509Certificate::from_der(&der)
            .map_err(|_| invalid("Malformed embedded signing certificate"))?;
        at = at.max(cert.validity().not_before.timestamp());
    }
    for bytes in &signed.crls {
        if bytes.len() > MAX_CRL_BYTES {
            return Err(invalid("Oversized embedded signing CRL"));
        }
        let (_, crl) = CertificateRevocationList::from_der(bytes)
            .map_err(|_| invalid("Malformed embedded signing CRL"))?;
        at = at.max(crl.last_update().timestamp());
    }
    Ok(at)
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

/// Bounded body and redirect count. Every hop retains HTTPS and a reviewed origin boundary.
pub async fn fetch_bounded(
    client: &reqwest::Client,
    source: &str,
    max: usize,
) -> Result<Vec<u8>, ErrorResponse> {
    let mut url =
        reqwest::Url::parse(source).map_err(|_| invalid("Invalid FIDO MDS source URL"))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(
            "FIDO MDS download requires HTTPS without URL credentials",
        ));
    }
    let origin = url.clone();
    let mut redirects = 0;
    let mut response = loop {
        let response = client.get(url.clone()).send().await?;
        if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            break response;
        }
        if redirects == 5 {
            return Err(invalid("Too many FIDO MDS redirects"));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| invalid("Missing FIDO MDS redirect location"))?;
        let target = url
            .join(location)
            .map_err(|_| invalid("Invalid FIDO MDS redirect"))?;
        if !redirect_allowed(&origin, &target) {
            return Err(invalid("Unsafe FIDO MDS redirect origin or scheme"));
        }
        url = target;
        redirects += 1;
    };
    if response.status().as_u16() == 429
        || (response.status().as_u16() == 503
            && response
                .headers()
                .contains_key(reqwest::header::RETRY_AFTER))
    {
        return Err(rate_limited(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
        ));
    }
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
    // The publisher also returns a small throttle message with HTTP 200.
    if bytes.len() <= 4096
        && std::str::from_utf8(&bytes).is_ok_and(|body| {
            let body = body.to_ascii_lowercase();
            [
                "rate limit",
                "too many requests",
                "throttl",
                "try again later",
            ]
            .iter()
            .any(|message| body.contains(message))
        })
    {
        return Err(rate_limited(None));
    }
    Ok(bytes)
}

fn redirect_allowed(origin: &reqwest::Url, target: &reqwest::Url) -> bool {
    let fido_host = |url: &reqwest::Url| {
        matches!(
            url.host_str(),
            Some("mds.fidoalliance.org" | "mds3.fidoalliance.org")
        )
    };
    target.scheme() == "https"
        && target.username().is_empty()
        && target.password().is_none()
        && target.fragment().is_none()
        && (target.origin() == origin.origin()
            || (fido_host(origin)
                && fido_host(target)
                && origin.port_or_known_default() == Some(443)
                && target.port_or_known_default() == Some(443)))
}

fn rate_limited(retry_after: Option<&str>) -> ErrorResponse {
    let now = chrono::Utc::now().timestamp();
    let delay = retry_after
        .and_then(|value| {
            value.parse::<i64>().ok().or_else(|| {
                chrono::DateTime::parse_from_rfc2822(value)
                    .ok()
                    .map(|date| date.timestamp().saturating_sub(now))
            })
        })
        .unwrap_or(3600)
        .clamp(60, 86400);
    ErrorResponse::new(
        ErrorResponseType::TooManyRequests(now.saturating_add(delay)),
        "FIDO MDS service requested retry backoff",
    )
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
