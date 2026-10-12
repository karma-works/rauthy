//! Persistence for the FIDO MDS dataset.
//!
//! The prepared dataset is embedded in the binary and seeded on startup when the tables are still
//! empty, which covers both a fresh instance and an existing one upgrading into this version.
//! Runtime updates revalidate the BLOB and signing-chain CRLs at least daily.
//!
//! The asset is produced by `just fido-mds-prep` and is not checked into the repository. When it
//! is missing in a debug build, `build.rs` substitutes an empty placeholder. Release builds require
//! an asset. Every startup verifies the embedded signature and fresh certificate/CRL evidence.

use crate::database::DB;
use crate::fido_mds::mds_entry::MdsEntry;
use crate::fido_mds::raw;
use crate::fido_mds::verified::{self, SignedBlob};
use crate::rauthy_config::RauthyConfig;
use hiqlite::{Params, params};
use rauthy_common::is_hiqlite;
use rauthy_common::utils::serialize;
use rauthy_error::ErrorResponse;
use serde::{Deserialize, Serialize};

use tracing::{info, warn};

/// The dataset shipped with the image, produced by the `fido-mds-prep` tool.
static MDS_DATASET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fido_mds_dataset.bin"));

const SQL_META_DELETE: &str = "DELETE FROM fido_mds_metadata WHERE current_blob_no != $1";
// Guard a non-primary NOT NULL column: SQLite INTEGER PRIMARY KEY replaces NULL with a rowid.
// Keep first appearances of $1..$4 in order for SQLite positional parameter binding.
const SQL_META: &str = r#"
INSERT INTO fido_mds_metadata (current_blob_no, next_update, blob_hash, verified_until)
VALUES (
    $1, $2,
    CASE WHEN EXISTS (
        SELECT 1 FROM fido_mds_metadata WHERE verified_until != 0 AND (
            current_blob_no > $1 OR (current_blob_no = $1 AND blob_hash != $3)
        )
    ) THEN NULL ELSE $3 END,
    $4
)
ON CONFLICT (current_blob_no) DO UPDATE SET next_update = $2, blob_hash = $3, verified_until = $4
"#;
const SQL_JOIN_DELETE: &str = "DELETE FROM fido_mds_entry_certs";
const SQL_ENTRIES_DELETE: &str = "DELETE FROM fido_mds_entries WHERE NOT EXISTS \
            (SELECT 1 FROM fido_mds_entry_certs j WHERE j.aaguid = fido_mds_entries.aaguid)";
const SQL_CERTS_DELETE: &str = "DELETE FROM fido_mds_certs WHERE NOT EXISTS \
            (SELECT 1 FROM fido_mds_entry_certs j WHERE j.cert_hash = fido_mds_certs.hash)";
const SQL_CERT: &str = r#"
INSERT INTO fido_mds_certs (hash, cert_der) VALUES ($1, $2)
ON CONFLICT (hash) DO UPDATE SET cert_der = $2
"#;
const SQL_ENTRY: &str = r#"
INSERT INTO fido_mds_entries (
    aaguid, description, key_protection, attachment_hint, attestation_types, cert_level
)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (aaguid) DO UPDATE SET description = $2, key_protection = $3, attachment_hint = $4,
attestation_types = $5, cert_level = $6
"#;
const SQL_JOIN: &str = r#"
INSERT INTO fido_mds_entry_certs (aaguid, cert_hash)
VALUES ($1, $2)
ON CONFLICT (aaguid, cert_hash) DO NOTHING
"#;

#[derive(Debug, Clone)]
pub struct MdsDataset {
    /// The monotonic MDS blob number (`no`). A higher value is newer.
    blob_no: i64,
    /// The `nextUpdate` the blob advertises, as a unix timestamp in seconds, for the scheduler.
    next_update_ts: i64,
    entries: Vec<MdsEntry>,
    /// Every distinct root certificate referenced by `entries`, deduplicated by hash.
    certs: Vec<MdsCert>,
    signed: SignedBlob,
    blob_hash: Vec<u8>,
    verified_until: i64,
}

/// A distinct root certificate, keyed by the SHA-256 of its DER encoding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MdsCert {
    pub hash: [u8; 32],
    pub cert_der: Vec<u8>,
}

impl MdsDataset {
    pub fn blob_no(&self) -> i64 {
        self.blob_no
    }
    pub fn next_update_ts(&self) -> i64 {
        self.next_update_ts
    }
    pub fn entries(&self) -> &[MdsEntry] {
        &self.entries
    }
    pub fn certs(&self) -> &[MdsCert] {
        &self.certs
    }

    /// Authenticate a BLOB and download fresh issuer CRLs before interpreting its payload.
    pub async fn from_jwt(jwt: &str) -> Result<Self, ErrorResponse> {
        let now = chrono::Utc::now().timestamp();
        let authenticated = verified::authenticate(jwt, now)?;
        let crls = verified::collect_crls(&authenticated.chain).await?;
        Self::from_signed(
            SignedBlob {
                jwt: jwt.to_string(),
                crls,
            },
            chrono::Utc::now().timestamp(),
        )
    }

    fn from_signed(signed: SignedBlob, now: i64) -> Result<Self, ErrorResponse> {
        let authenticated = verified::authenticate(&signed.jwt, now)?;
        verified::check_crls(&authenticated.chain, &signed.crls, now)?;
        let parsed = raw::transform(&authenticated.payload)?;
        validate_version(parsed.blob_no, parsed.next_update_ts, now, None)?;
        let blob_hash = openssl::sha::sha256(&authenticated.payload).to_vec();
        let verified_until = verified::verification_deadline(
            &authenticated.chain,
            &signed.crls,
            parsed.next_update_ts,
        )?;
        // Fail at ingestion rather than waiting until an attestation ceremony uses invalid roots.
        for cert in &parsed.certs {
            openssl::x509::X509::from_der(&cert.cert_der)?;
        }
        Ok(Self {
            blob_no: parsed.blob_no,
            next_update_ts: parsed.next_update_ts,
            entries: parsed.entries,
            certs: parsed.certs,
            signed,
            blob_hash,
            verified_until,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ErrorResponse> {
        serialize(&self.signed)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorResponse> {
        // The old unsigned prepared format deliberately no longer deserializes successfully.
        if bytes.len() > verified::MAX_BLOB_BYTES + 20 * 1024 * 1024 {
            return Err(verified::invalid(
                "Prepared FIDO MDS asset exceeds the size limit",
            ));
        }
        let (signed, consumed) = bincode_next::serde::decode_from_slice(
            bytes,
            bincode_next::config::legacy().with_limit::<{ 36 * 1024 * 1024 }>(),
        )
        .map_err(|_| verified::invalid("Invalid prepared FIDO MDS authentication evidence"))?;
        if consumed != bytes.len() {
            return Err(verified::invalid(
                "Trailing bytes in prepared FIDO MDS asset",
            ));
        }
        Self::from_signed(signed, chrono::Utc::now().timestamp())
    }
}

/// Reject stale/far-future metadata and prevent replay of previously accepted versions.
fn validate_version(
    blob_no: i64,
    next_update: i64,
    now: i64,
    previous: Option<i64>,
) -> Result<(), ErrorResponse> {
    if blob_no <= 0 || next_update <= now || next_update > now.saturating_add(90 * 86400) {
        return Err(verified::invalid(
            "FIDO MDS metadata is expired or has an invalid version/update date",
        ));
    }
    if previous.is_some_and(|previous| blob_no <= previous) {
        return Err(verified::invalid(
            "FIDO MDS BLOB replay or rollback rejected",
        ));
    }
    Ok(())
}

impl MdsDataset {
    /// Seed the embedded dataset when the entries table is empty. A no-op otherwise, so it is safe
    /// to call on every startup. Only the primary node writes; followers receive it through Raft.
    pub async fn seed_embedded() -> Result<(), ErrorResponse> {
        if !RauthyConfig::get().is_primary_node {
            return Ok(());
        }
        if MDS_DATASET.is_empty() {
            warn!(
                "This build contains no FIDO MDS dataset. Run `just fido-mds-prep` and rebuild to \
                 include one."
            );
            return Ok(());
        }
        // An authenticated empty snapshot is still a snapshot. Replaying an older embedded
        // asset here must neither resurrect withdrawn models nor prevent the server starting.
        let authenticated_snapshot = super::metadata::MdsMetadata::find()
            .await
            .is_ok_and(|metadata| metadata.verified_until != 0 && metadata.blob_hash.len() == 32);
        if authenticated_snapshot || Self::entries_count().await? > 0 {
            return Ok(());
        }

        let slf = match Self::deserialize(MDS_DATASET) {
            Ok(dataset) => dataset,
            Err(err) => {
                warn!(
                    "Embedded FIDO MDS authentication evidence is invalid or expired: {err}. \
                       Waiting for the verified online update."
                );
                return Ok(());
            }
        };
        slf.upsert().await?;

        info!(
            "Seeded FIDO MDS dataset no. {}: {} entries, {} root certs",
            slf.blob_no,
            slf.entries.len(),
            slf.certs.len(),
        );
        Ok(())
    }

    async fn entries_count() -> Result<i64, ErrorResponse> {
        let sql = "SELECT COUNT(*) AS count FROM fido_mds_entries";

        let count: i64 = if is_hiqlite() {
            DB::hql()
                .query_raw(sql, params!())
                .await?
                .remove(0)
                .get("count")
        } else {
            DB::pg_query_rows(sql, &[], 1).await?.remove(0).get("count")
        };
        Ok(count)
    }

    pub async fn upsert(&self) -> Result<(), ErrorResponse> {
        let now = chrono::Utc::now().timestamp();
        validate_version(self.blob_no, self.next_update_ts, now, None)?;
        if self.verified_until <= now {
            return Err(verified::invalid(
                "FIDO MDS signing-chain evidence has expired",
            ));
        }
        // The first statement enforces monotonicity in the DB transaction itself, including a
        // concurrent update on another process. A rollback or changed same-number payload
        // deliberately violates NOT NULL and rolls back before trusted entries are changed.

        if is_hiqlite() {
            let mut txn: Vec<(&str, Params)> =
                Vec::with_capacity(5 + self.certs.len() + self.entries.len() * 2);

            txn.push((
                SQL_META,
                params!(
                    self.blob_no,
                    self.next_update_ts,
                    self.blob_hash.clone(),
                    self.verified_until
                ),
            ));
            txn.push((SQL_JOIN_DELETE, params!()));

            for c in &self.certs {
                txn.push((SQL_CERT, params!(c.hash.to_vec(), c.cert_der.clone())));
            }
            for e in &self.entries {
                txn.push((
                    SQL_ENTRY,
                    params!(
                        e.aaguid.as_bytes().to_vec(),
                        e.description.clone(),
                        e.key_protection.bits() as i64,
                        e.attachment_hint.bits() as i64,
                        e.attestation_types.bits() as i64,
                        e.cert_level.as_u8() as i64
                    ),
                ));
                for h in &e.cert_hashes {
                    txn.push((SQL_JOIN, params!(e.aaguid.as_bytes().to_vec(), h.to_vec())));
                }
            }

            txn.push((SQL_ENTRIES_DELETE, params!()));
            txn.push((SQL_CERTS_DELETE, params!()));
            txn.push((SQL_META_DELETE, params!(self.blob_no)));

            for res in DB::hql().txn(txn).await? {
                res?;
            }
        } else {
            let mut cl = DB::pg().await?;
            let txn = cl.transaction().await?;

            let st_meta_delete = txn.prepare(SQL_META_DELETE).await?;
            let st_meta = txn.prepare(SQL_META).await?;
            let st_cert = txn.prepare(SQL_CERT).await?;
            let st_entry = txn.prepare(SQL_ENTRY).await?;
            let st_join = txn.prepare(SQL_JOIN).await?;

            // Serialize writers even when the metadata table is initially empty.
            txn.batch_execute("LOCK TABLE fido_mds_metadata IN EXCLUSIVE MODE")
                .await?;
            txn.execute(
                &st_meta,
                &[
                    &self.blob_no,
                    &self.next_update_ts,
                    &self.blob_hash,
                    &self.verified_until,
                ],
            )
            .await?;
            txn.batch_execute(SQL_JOIN_DELETE).await?;

            for c in &self.certs {
                let hash = c.hash.as_slice();

                txn.execute(&st_cert, &[&hash, &c.cert_der]).await?;
            }
            for e in &self.entries {
                let aaguid = e.aaguid.as_bytes().as_slice();
                let kp = e.key_protection.bits() as i64;
                let ah = e.attachment_hint.bits() as i64;
                let at = e.attestation_types.bits() as i64;
                let lvl = e.cert_level.as_u8() as i16;
                txn.execute(&st_entry, &[&aaguid, &e.description, &kp, &ah, &at, &lvl])
                    .await?;
                for h in &e.cert_hashes {
                    let hash = h.as_slice();
                    txn.execute(&st_join, &[&aaguid, &hash]).await?;
                }
            }

            txn.batch_execute(SQL_ENTRIES_DELETE).await?;
            txn.batch_execute(SQL_CERTS_DELETE).await?;
            txn.execute(&st_meta_delete, &[&self.blob_no]).await?;
            txn.commit().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;
