use crate::database::DB;
use hiqlite::macros::FromRow;
use hiqlite::params;
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize, FromRow, FromPgRow)]
pub struct MdsMetadata {
    pub current_blob_no: i64,
    pub next_update: i64,
    #[serde(default)]
    pub blob_hash: Vec<u8>,
    #[serde(default)]
    pub verified_until: i64,
}

impl MdsMetadata {
    pub async fn require_verified() -> Result<Self, ErrorResponse> {
        let metadata = Self::find().await?;
        if !metadata.has_verified_snapshot() {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "FIDO MDS snapshot has not been authenticated",
            ));
        }
        let now = chrono::Utc::now().timestamp();
        static LAST_WARNING: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
        let last = LAST_WARNING.load(std::sync::atomic::Ordering::Relaxed);
        if !metadata.is_current(now)
            && now.saturating_sub(last) >= 3600
            && LAST_WARNING
                .compare_exchange(
                    last,
                    now,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        {
            tracing::warn!("Using last-known-good FIDO MDS metadata; an online refresh is due");
        }
        Ok(metadata)
    }

    pub fn has_verified_snapshot(&self) -> bool {
        self.current_blob_no > 0 && self.blob_hash.len() == 32 && self.verified_until > 0
    }

    pub(super) fn cache_tag(&self) -> String {
        format!(
            "{}_{}_{}",
            self.current_blob_no,
            rauthy_common::utils::base64_url_no_pad_encode(&self.blob_hash),
            self.verified_until
        )
    }

    pub(super) fn is_current(&self, now: i64) -> bool {
        self.has_verified_snapshot() && self.verified_until > now && self.next_update > now
    }

    pub async fn find() -> Result<Self, ErrorResponse> {
        let sql = "SELECT * FROM fido_mds_metadata";
        let slf = if is_hiqlite() {
            DB::hql().query_map_one(sql, params!()).await?
        } else {
            DB::pg_query_one(sql, &[]).await?
        };
        Ok(slf)
    }
}
