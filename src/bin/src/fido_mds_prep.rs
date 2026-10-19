//! Offline tool that regenerates the shipped FIDO MDS dataset.
//!
//! It downloads (or reads) the raw MDS blob, runs the exact transform the server uses, and writes
//! the serialized [`MdsDataset`] to the asset the server embeds at compile time. Run it via the
//! `just fido-mds-prep` recipe rather than directly.
//!
//! The prepared asset retains the signed BLOB and fresh signing-chain CRLs. HTTPS protects the
//! transport; the same pinned-root/signature/revocation checks apply to URLs and local BLOB files.
//! Verification still requires network access to the signing certificates' issuer CRLs.

use clap::Parser;
use rauthy_data::fido_mds::dataset::MdsDataset;
use rauthy_data::fido_mds::verified::{MAX_BLOB_BYTES, MDS_SOURCE, fetch_bounded, http_client};
use std::error::Error;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_SOURCE: &str = MDS_SOURCE;
const DEFAULT_OUT: &str = "assets/fido_mds/dataset.bin";

#[derive(Debug, Parser)]
#[clap(
    author,
    version,
    about = "Prepares the FIDO MDS dataset Rauthy embeds at compile time",
    long_about = None
)]
struct Args {
    /// The MDS blob to transform: an `https://` URL, or a path to a local file.
    #[clap(short, long, default_value = DEFAULT_SOURCE)]
    source: String,
    /// Where to write the prepared dataset.
    #[clap(short, long, default_value = DEFAULT_OUT)]
    out: PathBuf,
}

/// The metadata service rate-limits, and answers a throttled request with `200 OK` and a plain
/// text body rather than a status code, so the response has to be sniffed rather than trusted.
/// A release build fetches the dataset, so a transient throttle must not fail it outright.
const DOWNLOAD_ATTEMPTS: u32 = 5;

async fn download(source: &str) -> Result<String, Box<dyn Error>> {
    let client = http_client().map_err(|err| err.to_string())?;
    download_using(&client, source).await
}

async fn download_using(client: &reqwest::Client, source: &str) -> Result<String, Box<dyn Error>> {
    let mut last_err = String::new();
    let mut retry_at = 0i64;
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        if attempt > 1 {
            let backoff = Duration::from_secs(
                2u64.pow(attempt - 1).max(
                    retry_at
                        .saturating_sub(chrono::Utc::now().timestamp())
                        .max(0) as u64,
                ),
            );
            println!("Retrying in {}s: {last_err}", backoff.as_secs());
            tokio::time::sleep(backoff).await;
        }

        match fetch_bounded(client, source, MAX_BLOB_BYTES).await {
            Ok(bytes) => {
                let body = match String::from_utf8(bytes) {
                    Ok(body) => body,
                    Err(err) => {
                        last_err = err.to_string();
                        continue;
                    }
                };
                if body.trim().split('.').count() == 3 {
                    return Ok(body);
                }
                last_err = "the metadata service did not return a compact JWS".into();
            }
            Err(err) => {
                retry_at = match err.error {
                    rauthy_error::ErrorResponseType::TooManyRequests(until) => until,
                    _ => 0,
                };
                last_err = err.to_string();
            }
        }
    }

    Err(format!("giving up after {DOWNLOAD_ATTEMPTS} attempts, {last_err}").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let jwt = if args.source.starts_with("http://") {
        return Err("refusing to download the FIDO MDS blob over plain http".into());
    } else if args.source.starts_with("https://") {
        println!("Downloading FIDO MDS blob from {}", args.source);
        download(&args.source).await?
    } else if args.source.contains("://") {
        return Err(format!(
            "unsupported FIDO MDS source scheme in {:?}, expected `https://` or a file path",
            args.source
        )
        .into());
    } else {
        println!("Reading FIDO MDS blob from {}", args.source);
        let mut bytes = Vec::new();
        std::fs::File::open(&args.source)?
            .take(MAX_BLOB_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_BLOB_BYTES {
            return Err("FIDO MDS input exceeds the size limit".into());
        }
        String::from_utf8(bytes)?
    };

    let dataset = MdsDataset::from_jwt(jwt.trim())
        .await
        .map_err(|err| err.to_string())?;
    let next_update = chrono::DateTime::from_timestamp(dataset.next_update_ts(), 0)
        .map(|dt| dt.date_naive().to_string())
        .unwrap_or_else(|| dataset.next_update_ts().to_string());
    println!(
        "Prepared blob no. {}, nextUpdate {}: {} entries, {} distinct root certs",
        dataset.blob_no(),
        next_update,
        dataset.entries().len(),
        dataset.certs().len(),
    );

    let bytes = dataset.serialize().map_err(|err| err.to_string())?;
    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.out, &bytes)?;
    println!("Wrote {} bytes to {}", bytes.len(), args.out.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_utf8_response_is_retried() {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::ssl::{SslAcceptor, SslMethod};
        use openssl::x509::{X509, X509NameBuilder};
        use std::io::Write;

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let mut tls = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        tls.set_private_key(&key).unwrap();
        tls.set_certificate(&cert.build()).unwrap();
        let tls = tls.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for body in [vec![0xff], b"a.b.c".to_vec()] {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut stream = tls.accept(stream).unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).unwrap() > 0);
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        // Only the local response fixture bypasses TLS trust; production uses http_client().
        let client = reqwest::Client::builder()
            .no_proxy()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let body = download_using(&client, &format!("https://localhost:{}/", addr.port()))
            .await
            .unwrap();
        assert_eq!(body, "a.b.c");
        server.join().unwrap();
    }
}
