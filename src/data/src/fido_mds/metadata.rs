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
    pub async fn require_current() -> Result<Self, ErrorResponse> {
        let metadata = Self::find().await?;
        if !metadata.is_current(chrono::Utc::now().timestamp()) {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "FIDO MDS authentication evidence has expired",
            ));
        }
        Ok(metadata)
    }

    pub(super) fn is_current(&self, now: i64) -> bool {
        self.blob_hash.len() == 32 && self.verified_until > now && self.next_update > now
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
