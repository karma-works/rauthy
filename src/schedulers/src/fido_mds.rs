use chrono::Utc;
use rauthy_data::database::DB;
use rauthy_data::fido_mds::dataset::MdsDataset;
use rauthy_data::fido_mds::metadata::MdsMetadata;
use rauthy_data::fido_mds::verified::{MAX_BLOB_BYTES, MDS_SOURCE, fetch_bounded, http_client};
use rauthy_data::rauthy_config::RauthyConfig;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info};

pub async fn fido_mds_updater() {
    {
        let config = &RauthyConfig::get().vars.webauthn;
        if !config.optimistic_attestation
            && config.force_passkey_cert_level.is_none()
            && config.force_passkey_protection.is_none()
            && config.force_passkey_attachment.is_none()
        {
            info!("No FIDO device attestation configured. Exiting update scheduler.");
            return;
        }
    }
    time::sleep(Duration::from_secs(3)).await;

    let mut failures = 0u32;
    let initial = MdsMetadata::find().await.unwrap_or_default();
    let mut delay = refresh_delay(&initial, Utc::now().timestamp(), 0);
    loop {
        time::sleep(Duration::from_secs(delay)).await;
        let meta = MdsMetadata::find().await.unwrap_or_default();
        if !DB::hql().is_leader_cache().await {
            debug!("Not the cache leader, skipping FIDO MDS update");
            time::sleep(Duration::from_secs(60)).await;
            continue;
        }
        debug!("Running fido_mds_updater scheduler: {meta:?}");

        match exec().await {
            Ok(()) => {
                failures = 0;
                let meta = MdsMetadata::find().await.unwrap_or_default();
                delay = refresh_delay(&meta, Utc::now().timestamp(), 3600);
            }
            Err(err) => {
                failures = failures.saturating_add(1);
                delay = retry_delay(failures, &err, Utc::now().timestamp());
                error!("Error running fido_mds_updater: {err:?}; retry in {delay}s");
            }
        }
    }
}

async fn exec() -> Result<(), ErrorResponse> {
    let client = http_client()?;
    let bytes = fetch_bounded(&client, MDS_SOURCE, MAX_BLOB_BYTES).await?;
    let body = std::str::from_utf8(&bytes).map_err(|_| {
        ErrorResponse::new(
            rauthy_error::ErrorResponseType::BadRequest,
            "FIDO MDS BLOB is not UTF-8",
        )
    })?;
    let dataset = MdsDataset::from_jwt(body.trim()).await?;
    dataset.upsert().await?;
    info!(
        "Authenticated FIDO MDS dataset updated. blob_no: {}, next_update: {}",
        dataset.blob_no(),
        dataset.next_update_ts()
    );
    Ok(())
}

fn refresh_delay(meta: &MdsMetadata, now: i64, minimum: i64) -> u64 {
    meta.next_update
        .min(meta.verified_until)
        .saturating_sub(3600)
        .saturating_sub(now)
        .clamp(minimum, 86400) as u64
}

fn retry_delay(failures: u32, err: &ErrorResponse, now: i64) -> u64 {
    let backoff = (600u64 * (1u64 << failures.saturating_sub(1).min(6))).min(21600);
    match err.error {
        ErrorResponseType::TooManyRequests(until) => {
            backoff.max(until.saturating_sub(now).clamp(0, 86400) as u64)
        }
        _ => backoff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_backoff_and_server_deadline() {
        let err = ErrorResponse::new(ErrorResponseType::Connection, "offline");
        assert_eq!(retry_delay(1, &err, 100), 600);
        assert_eq!(retry_delay(2, &err, 100), 1200);
        assert_eq!(retry_delay(100, &err, 100), 21600);
        let limited = ErrorResponse::new(ErrorResponseType::TooManyRequests(43300), "throttled");
        assert_eq!(retry_delay(1, &limited, 100), 43200);
        assert_eq!(refresh_delay(&MdsMetadata::default(), 100, 3600), 3600);
        assert_eq!(refresh_delay(&MdsMetadata::default(), 100, 0), 0);
        let fresh = MdsMetadata {
            next_update: 100 + 7 * 86400,
            verified_until: 100 + 2 * 86400,
            ..Default::default()
        };
        assert_eq!(refresh_delay(&fresh, 100, 0), 86400);
    }
}
