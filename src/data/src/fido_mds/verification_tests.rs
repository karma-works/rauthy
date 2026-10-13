use super::*;
use openssl::bn::BigNum;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{CrlNumber, X509CrlBuilder, X509NameBuilder, X509RevokedBuilder};
use rauthy_common::utils::{base64_encode, base64_url_no_pad_encode};
use serde_json::json;
use std::sync::OnceLock;

const NOW: i64 = 1_791_806_400;
struct Fixture {
    root_key: PKey<Private>,
    root: X509,
    leaf_key: PKey<Private>,
    leaf: X509,
}

fn certificate(
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    dns: &str,
    signature_usage: bool,
) -> X509 {
    certificate_at(key, issuer, dns, signature_usage, NOW)
}

fn certificate_at(
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    dns: &str,
    signature_usage: bool,
    now: i64,
) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(
            &BigNum::from_u32(if issuer.is_some() { 2 } else { 1 })
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(now - 86400).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(now + 86400 * 30).unwrap())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", dns).unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&name))
        .unwrap();
    if let Some((issuer, _)) = issuer {
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        let mut usage = KeyUsage::new();
        usage.critical();
        if signature_usage {
            usage.digital_signature();
        } else {
            usage.key_encipherment();
        }
        builder.append_extension(usage.build().unwrap()).unwrap();
        builder
            .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns(dns)
            .build(&builder.x509v3_context(Some(issuer), None))
            .unwrap();
        builder.append_extension(san).unwrap();
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(issuer), None))
            .unwrap();
        builder.append_extension(aki).unwrap();
    } else {
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
    }
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(issuer.map(|(c, _)| &**c), None))
        .unwrap();
    builder.append_extension(ski).unwrap();
    builder
        .sign(
            issuer.map(|(_, k)| k).unwrap_or(key),
            MessageDigest::sha256(),
        )
        .unwrap();
    builder.build()
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let root = certificate(&root_key, None, "Test MDS root", true);
        let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let leaf = certificate(
            &leaf_key,
            Some((&root, &root_key)),
            "mds.fidoalliance.org",
            true,
        );
        Fixture {
            root_key,
            root,
            leaf_key,
            leaf,
        }
    })
}

fn jwt(header: serde_json::Value, payload: &[u8], key: &PKey<Private>) -> String {
    let input = format!(
        "{}.{}",
        base64_url_no_pad_encode(&serde_json::to_vec(&header).unwrap()),
        base64_url_no_pad_encode(payload)
    );
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(input.as_bytes()).unwrap();
    format!(
        "{input}.{}",
        base64_url_no_pad_encode(&signer.sign_to_vec().unwrap())
    )
}

fn header(leaf: &X509) -> serde_json::Value {
    json!({"alg":"RS256","typ":"JWT","x5c":[base64_encode(&leaf.to_der().unwrap())]})
}

fn crl(issuer: &X509, signing_key: &PKey<Private>, revoked: bool, next_update: i64) -> Vec<u8> {
    let mut builder = X509CrlBuilder::new().unwrap();
    builder.set_issuer_name(issuer.subject_name()).unwrap();
    builder
        .set_last_update(&Asn1Time::from_unix(NOW - 60).unwrap())
        .unwrap();
    builder
        .set_next_update(&Asn1Time::from_unix(next_update).unwrap())
        .unwrap();
    let dummy = X509::builder().unwrap();
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&dummy.x509v3_context(Some(issuer), None))
        .unwrap();
    builder.append_extension(aki).unwrap();
    builder
        .append_extension(
            CrlNumber::new(BigNum::from_u32(1).unwrap())
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap();
    if revoked {
        let mut revoked = X509RevokedBuilder::new().unwrap();
        revoked
            .set_serial_number(fixture().leaf.serial_number())
            .unwrap();
        revoked
            .set_revocation_date(&Asn1Time::from_unix(NOW - 30).unwrap())
            .unwrap();
        builder.add_revoked(revoked.build()).unwrap();
    }
    builder.sign(signing_key, MessageDigest::sha256()).unwrap();
    builder.build().unwrap().to_der().unwrap()
}

#[test]
fn verifies_signed_blob_and_fresh_nonrevoked_chain() {
    let f = fixture();
    let jwt = jwt(header(&f.leaf), br#"{"no":290}"#, &f.leaf_key);
    let authenticated = authenticate_with_root(&jwt, NOW, &f.root).unwrap();
    assert_eq!(authenticated.payload, br#"{"no":290}"#);
    let crls = [crl(&f.root, &f.root_key, false, NOW + 3600)];
    check_crls(&authenticated.chain, &crls, NOW).unwrap();
    assert_eq!(
        verification_deadline(&authenticated.chain, &crls).unwrap(),
        NOW + 3600
    );
}

#[test]
fn rejects_tampered_payload_and_signature() {
    let f = fixture();
    let original = jwt(header(&f.leaf), br#"{"no":290}"#, &f.leaf_key);
    let mut parts: Vec<String> = original.split('.').map(str::to_owned).collect();
    parts[1] = base64_url_no_pad_encode(br#"{"no":291}"#);
    assert!(authenticate_with_root(&parts.join("."), NOW, &f.root).is_err());
    let mut parts: Vec<String> = original.split('.').map(str::to_owned).collect();
    let mut signature = base64_url_no_pad_decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = base64_url_no_pad_encode(&signature);
    assert!(authenticate_with_root(&parts.join("."), NOW, &f.root).is_err());
}

#[test]
fn rejects_wrong_root_expired_certificate_and_unrelated_signer() {
    let f = fixture();
    let signed = jwt(header(&f.leaf), b"{}", &f.leaf_key);
    assert!(authenticate(&signed, NOW).is_err());
    assert!(authenticate_with_root(&signed, NOW + 86400 * 31, &f.root).is_err());
    assert!(authenticate_with_root(&signed, NOW - 86401, &f.root).is_err());
    for (dns, usage) in [
        ("attacker.example", true),
        ("*.fidoalliance.org", true),
        ("mds.fidoalliance.org", false),
    ] {
        let leaf = certificate(&f.leaf_key, Some((&f.root, &f.root_key)), dns, usage);
        assert!(
            authenticate_with_root(&jwt(header(&leaf), b"{}", &f.leaf_key), NOW, &f.root).is_err()
        );
    }
}

#[test]
fn rejects_algorithm_confusion_remote_headers_and_malformed_jws() {
    let f = fixture();
    for alg in ["none", "HS256", "ES256", "RS512"] {
        let mut h = header(&f.leaf);
        h["alg"] = json!(alg);
        assert!(authenticate_with_root(&jwt(h, b"{}", &f.leaf_key), NOW, &f.root).is_err());
    }
    for (field, value) in [
        ("x5u", json!("https://attacker.example/cert")),
        ("jku", json!("http://127.0.0.1/")),
        ("crit", json!(["b64"])),
        ("b64", json!(false)),
    ] {
        let mut h = header(&f.leaf);
        h[field] = value;
        assert!(authenticate_with_root(&jwt(h, b"{}", &f.leaf_key), NOW, &f.root).is_err());
    }
    for input in ["", "a.b", "a.b.c.d", "a..c", "aaaa.e30.zzzz"] {
        assert!(authenticate_with_root(input, NOW, &f.root).is_err());
    }
    let duplicates = format!(
        r#"{{"alg":"RS256","alg":"none","x5c":["{}"]}}"#,
        base64_encode(&f.leaf.to_der().unwrap())
    );
    let duplicate_jws = format!(
        "{}.e30.aaaa",
        base64_url_no_pad_encode(duplicates.as_bytes())
    );
    assert!(authenticate_with_root(&duplicate_jws, NOW, &f.root).is_err());
}

#[test]
fn rejects_revoked_stale_missing_or_wrongly_signed_crls() {
    let f = fixture();
    let chain = [f.leaf.clone(), f.root.clone()];
    assert!(check_crls(&chain, &[], NOW).is_err());
    // A correctly signed CRL from the future is not usable yet.
    assert!(
        check_crls(
            &chain,
            &[crl(&f.root, &f.root_key, false, NOW + 3600)],
            NOW - 120,
        )
        .is_err()
    );
    for bytes in [
        crl(&f.root, &f.root_key, true, NOW + 3600),
        crl(&f.root, &f.root_key, false, NOW),
        crl(&f.root, &f.leaf_key, false, NOW + 3600),
        vec![0, 1, 2],
    ] {
        assert!(check_crls(&chain, &[bytes], NOW).is_err());
    }
    let mut bytes = crl(&f.root, &f.root_key, false, NOW + 3600);
    bytes.push(0);
    assert!(check_crls(&chain, &[bytes], NOW).is_err());
}

#[test]
fn prepared_asset_rejects_unsigned_or_malformed_evidence() {
    // An old unsigned dataset or a forged prepared asset must not create trusted DB rows.
    let unsigned = rauthy_common::utils::serialize(&vec![1u8, 2, 3]).unwrap();
    assert!(crate::fido_mds::dataset::MdsDataset::deserialize(&unsigned).is_err());
    let forged = SignedBlob {
        jwt: "aaaa.e30.zzzz".into(),
        crls: vec![],
    };
    let bytes = rauthy_common::utils::serialize(&forged).unwrap();
    assert!(crate::fido_mds::dataset::MdsDataset::deserialize(&bytes).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(crate::fido_mds::dataset::MdsDataset::deserialize(&trailing).is_err());
}

/// Explicit opt-in: public official BLOB/CRLs are fetched; ordinary unit tests stay offline.
#[tokio::test]
#[ignore = "requires live public FIDO/GlobalSign network access"]
async fn authenticates_current_official_blob() {
    let client = http_client().unwrap();
    // A cached official BLOB lets us exercise the actual verifier during publisher throttling.
    // Its signature and freshness are checked normally, and issuer CRLs are fetched live.
    let bytes = if let Ok(path) = std::env::var("RAUTHY_MDS_TEST_BLOB") {
        std::fs::read(path).unwrap()
    } else {
        fetch_bounded(&client, MDS_SOURCE, MAX_BLOB_BYTES)
            .await
            .unwrap()
    };
    let jwt = std::str::from_utf8(&bytes).unwrap();
    let dataset = crate::fido_mds::dataset::MdsDataset::from_jwt(jwt.trim())
        .await
        .unwrap();
    assert!(dataset.blob_no() > 0);
    assert!(!dataset.entries().is_empty());
    assert!(!dataset.certs().is_empty());
    let asset = dataset.serialize().unwrap();
    let restored = crate::fido_mds::dataset::MdsDataset::deserialize(&asset).unwrap();
    assert_eq!(restored.blob_no(), dataset.blob_no());
    assert_eq!(restored.certs(), dataset.certs());
}

#[test]
fn accepts_noncritical_header_extensions() {
    let f = fixture();
    let mut h = header(&f.leaf);
    h["kid"] = json!("rotation-key");
    h["future_hint"] = json!(true);
    let signed = jwt(h, b"{}", &f.leaf_key);
    authenticate_with_root(&signed, NOW, &f.root).unwrap();
}

#[test]
fn embedded_evidence_is_verified_at_issuer_signed_time() {
    let f = fixture();
    let signed = SignedBlob {
        jwt: jwt(header(&f.leaf), b"{}", &f.leaf_key),
        crls: vec![crl(&f.root, &f.root_key, false, NOW + 3600)],
    };
    let at = embedded_verification_time(&signed).unwrap();
    assert_eq!(at, NOW - 60);
    let authenticated = authenticate_with_root(&signed.jwt, at, &f.root).unwrap();
    check_crls(&authenticated.chain, &signed.crls, at).unwrap();
    assert!(check_crls(&authenticated.chain, &signed.crls, NOW + 86400 * 14).is_err());
    let revoked = [crl(&f.root, &f.root_key, true, NOW + 3600)];
    assert!(check_crls(&authenticated.chain, &revoked, at).is_err());
}

#[test]
fn redirects_preserve_transport_and_origin_boundaries() {
    let origin = reqwest::Url::parse(MDS_SOURCE).unwrap();
    for url in [
        "https://mds.fidoalliance.org/blob",
        "https://mds3.fidoalliance.org/blob",
    ] {
        assert!(redirect_allowed(
            &origin,
            &reqwest::Url::parse(url).unwrap()
        ));
    }
    for url in [
        "http://mds.fidoalliance.org/",
        "https://127.0.0.1/",
        "https://attacker.example/",
        "https://user@mds.fidoalliance.org/",
        "https://mds3.fidoalliance.org:444/",
    ] {
        assert!(!redirect_allowed(
            &origin,
            &reqwest::Url::parse(url).unwrap()
        ));
    }
    let crl = reqwest::Url::parse("https://crl.globalsign.com/root.crl").unwrap();
    assert!(redirect_allowed(&crl, &crl.join("other.crl").unwrap()));
    assert!(!redirect_allowed(&crl, &origin));
    let limited = rate_limited(Some("7200"));
    assert!(
        matches!(limited.error, ErrorResponseType::TooManyRequests(until)
        if until >= chrono::Utc::now().timestamp() + 7199)
    );
}

/// Exercise the real HTTP reader with a local TLS peer, including redirect and error responses.
#[tokio::test]
async fn https_download_follows_redirects_and_honors_limits_and_throttling() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    use std::io::{Read, Write};
    let f = fixture();
    let now = chrono::Utc::now().timestamp();
    let root = certificate_at(&f.root_key, None, "Test TLS root", true, now);
    let leaf = certificate_at(
        &f.leaf_key,
        Some((&root, &f.root_key)),
        "mds.fidoalliance.org",
        true,
        now,
    );
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&f.leaf_key).unwrap();
    acceptor.set_certificate(&leaf).unwrap();
    let acceptor = acceptor.build();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: /blob\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\na.b.c",
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7200\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\na.b.c",
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nrate limit",
        ] {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut stream = acceptor.accept(stream).unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_der(&root.to_der().unwrap()).unwrap())
        .resolve("mds.fidoalliance.org", addr)
        .build()
        .unwrap();
    let source = format!("https://mds.fidoalliance.org:{}/", addr.port());
    assert_eq!(
        fetch_bounded(&client, &source, 1024).await.unwrap(),
        b"a.b.c"
    );
    assert!(matches!(
        fetch_bounded(&client, &source, 1024)
            .await
            .unwrap_err()
            .error,
        ErrorResponseType::TooManyRequests(_)
    ));
    assert!(fetch_bounded(&client, &source, 4).await.is_err());
    assert!(matches!(
        fetch_bounded(&client, &source, 1024)
            .await
            .unwrap_err()
            .error,
        ErrorResponseType::TooManyRequests(_)
    ));
    server.join().unwrap();
}
