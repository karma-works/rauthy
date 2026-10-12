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

    let mut last_err = String::new();
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        if attempt > 1 {
            let backoff = Duration::from_secs(2u64.pow(attempt - 1));
            println!("Retrying in {}s: {last_err}", backoff.as_secs());
            tokio::time::sleep(backoff).await;
        }

        match fetch_bounded(&client, source, MAX_BLOB_BYTES).await {
            Ok(bytes) => {
                let body = String::from_utf8(bytes)?;
                if body.trim().split('.').count() == 3 {
                    return Ok(body);
                }
                last_err = "the metadata service did not return a compact JWS".into();
            }
            Err(err) => last_err = err.to_string(),
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
