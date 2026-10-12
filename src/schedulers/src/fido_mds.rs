use chrono::Utc;
use rauthy_data::database::DB;
use rauthy_data::fido_mds::authenticator::MdsAuthenticator;
use rauthy_data::fido_mds::dataset::MdsDataset;
use rauthy_data::fido_mds::metadata::MdsMetadata;
use rauthy_data::fido_mds::verified::{MAX_BLOB_BYTES, MDS_SOURCE, fetch_bounded, http_client};
use rauthy_data::rauthy_config::RauthyConfig;
use rauthy_error::ErrorResponse;
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

    loop {
        let meta = MdsMetadata::find().await.unwrap_or_default();
        let now = Utc::now().timestamp();
        // Poll daily, before the BLOB or signing-chain evidence expires. Legacy metadata has
        // verified_until=0 and must be refreshed immediately, irrespective of nextUpdate.
        let wake_at = meta
            .next_update
            .min(meta.verified_until)
            .saturating_sub(3600)
            .min(now + 86400);
        if wake_at > now {
            time::sleep(Duration::from_secs((wake_at - now) as u64)).await;
        }

        if !DB::hql().is_leader_cache().await {
            debug!("Not the cache leader, skipping FIDO MDS update");
            time::sleep(Duration::from_secs(60)).await;
            continue;
        }
        debug!("Running fido_mds_updater scheduler: {meta:?}");

        if let Err(err) = exec().await {
            error!("Error running fido_mds_updater: {err:?}");
        };

        // Avoid busy loop in error cases. We want to retry without hammering the servers.
        time::sleep(Duration::from_secs(600)).await;
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
    MdsAuthenticator::clear_cache().await?;
    info!(
        "Authenticated FIDO MDS dataset updated. blob_no: {}, next_update: {}",
        dataset.blob_no(),
        dataset.next_update_ts()
    );
    Ok(())
}
