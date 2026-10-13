use super::*;
use crate::fido_mds::metadata::MdsMetadata;
use rusqlite::{Connection, params};

const NOW: i64 = 1_791_806_400;
const A: &[u8] = &[1; 16];
const B: &[u8] = &[2; 16];
const C: &[u8] = &[3; 16];

fn sqlite() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE passkeys (id TEXT PRIMARY KEY);")
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../../../../migrations/hiqlite/35_fido_mds.sql"
        ))
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../../../../migrations/hiqlite/39_fido_mds_verification.sql"
        ))
        .unwrap();
    connection
}

/// Exercises the same statements as the Hiqlite transaction, on a disposable SQLite database.
fn sqlite_replace(
    connection: &mut Connection,
    no: i64,
    hash: &[u8],
    entries: &[(&[u8], &[u8])],
    verified: i64,
) -> rusqlite::Result<()> {
    let txn = connection.transaction()?;
    txn.execute(SQL_META, params![no, NOW + 86400, hash, verified])?;
    txn.execute(SQL_JOIN_DELETE, [])?;
    for (id, root) in entries {
        txn.execute(SQL_CERT, params![root, root])?;
        txn.execute(SQL_ENTRY, params![id, "Device", 1i64, 1i64, 1i64, 1i64])?;
        txn.execute(SQL_JOIN, params![id, root])?;
    }
    txn.execute(SQL_ENTRIES_DELETE, [])?;
    txn.execute(SQL_CERTS_DELETE, [])?;
    txn.execute(SQL_META_DELETE, params![no])?;
    txn.commit()
}

#[test]
fn sqlite_replacement_removes_revoked_models_roots_and_associations() {
    let mut connection = sqlite();
    sqlite_replace(
        &mut connection,
        1,
        &[1; 32],
        &[(A, b"root-old"), (B, b"root-revoked")],
        NOW + 3600,
    )
    .unwrap();
    connection
        .execute(
            "INSERT INTO passkeys (id, aaguid) VALUES ('kept',$1),('revoked',$2)",
            params![A, B],
        )
        .unwrap();
    sqlite_replace(
        &mut connection,
        2,
        &[2; 32],
        &[(A, b"root-new"), (C, b"root-other")],
        NOW + 7200,
    )
    .unwrap();
    let roots: Vec<Vec<u8>> = connection
        .prepare("SELECT cert_der FROM fido_mds_certs ORDER BY cert_der")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(roots, [b"root-new".to_vec(), b"root-other".to_vec()]);
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM fido_mds_entries WHERE aaguid=$1",
            params![B],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let kept: Option<Vec<u8>> = connection
        .query_row("SELECT aaguid FROM passkeys WHERE id='kept'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let revoked: Option<Vec<u8>> = connection
        .query_row("SELECT aaguid FROM passkeys WHERE id='revoked'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(kept.as_deref(), Some(A));
    assert_eq!(revoked, None);
    let old_join: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM fido_mds_entry_certs WHERE cert_hash=$1",
            params![b"root-old"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_join, 0);
}

#[test]
fn sqlite_rejects_rollback_changed_same_version_and_rolls_back_atomically() {
    let mut connection = sqlite();
    sqlite_replace(&mut connection, 2, &[2; 32], &[(A, b"root")], NOW + 3600).unwrap();
    assert!(sqlite_replace(&mut connection, 1, &[1; 32], &[(B, b"bad")], NOW + 7200).is_err());
    assert!(sqlite_replace(&mut connection, 2, &[3; 32], &[(B, b"bad")], NOW + 7200).is_err());
    let version: i64 = connection
        .query_row("SELECT current_blob_no FROM fido_mds_metadata", [], |r| {
            r.get(0)
        })
        .unwrap();
    let root: Vec<u8> = connection
        .query_row("SELECT cert_der FROM fido_mds_certs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
    assert_eq!(root, b"root");
    sqlite_replace(&mut connection, 2, &[2; 32], &[(A, b"root")], NOW + 7200).unwrap();
    let verified: i64 = connection
        .query_row("SELECT verified_until FROM fido_mds_metadata", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(verified, NOW + 7200);
}

#[test]
fn sqlite_empty_authenticated_snapshot_preserves_rollback_protection() {
    let mut connection = sqlite();
    sqlite_replace(&mut connection, 1, &[1; 32], &[(A, b"root")], NOW + 3600).unwrap();
    sqlite_replace(&mut connection, 2, &[2; 32], &[], NOW + 7200).unwrap();
    let entries: i64 = connection
        .query_row("SELECT COUNT(*) FROM fido_mds_entries", [], |r| r.get(0))
        .unwrap();
    let roots: i64 = connection
        .query_row("SELECT COUNT(*) FROM fido_mds_certs", [], |r| r.get(0))
        .unwrap();
    assert_eq!((entries, roots), (0, 0));
    assert!(sqlite_replace(&mut connection, 1, &[1; 32], &[(A, b"root")], NOW + 7200).is_err());
    let version: i64 = connection
        .query_row("SELECT current_blob_no FROM fido_mds_metadata", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(version, 2);
}

#[test]
fn legacy_is_untrusted_but_expired_verified_snapshot_remains_usable() {
    let mut connection = sqlite();
    connection
        .execute(
            "INSERT INTO fido_mds_metadata(current_blob_no,next_update) VALUES (9999,$1)",
            params![NOW + 86400],
        )
        .unwrap();
    let mut metadata = MdsMetadata {
        current_blob_no: 9999,
        next_update: NOW + 86400,
        blob_hash: vec![],
        verified_until: 0,
    };
    assert!(!metadata.is_current(NOW));
    // An untrusted legacy version number cannot pin the instance above authentic metadata.
    sqlite_replace(&mut connection, 1, &[1; 32], &[(A, b"root")], NOW + 3600).unwrap();
    metadata.blob_hash = vec![1; 32];
    metadata.verified_until = NOW + 3600;
    assert!(metadata.is_current(NOW));
    assert!(!metadata.is_current(NOW + 3600));
    assert!(validate_version(1, NOW, NOW).is_ok());
    assert!(validate_version(1, NOW + 91 * 86400, NOW).is_err());
    assert!(metadata.has_verified_snapshot());
    assert!(validate_version(1, NOW - PUBLICATION_GRACE, NOW).is_err());
    assert!(validate_version(2, NOW + 3600, NOW).is_ok());
}

async fn pg_replace(
    client: &mut tokio_postgres::Client,
    no: i64,
    hash: &[u8],
    entries: &[(&[u8], &[u8])],
    verified: i64,
) -> Result<(), tokio_postgres::Error> {
    let txn = client.transaction().await?;
    txn.batch_execute("LOCK TABLE fido_mds_metadata IN EXCLUSIVE MODE")
        .await?;
    txn.execute(SQL_META, &[&no, &(NOW + 86400), &hash, &verified])
        .await?;
    txn.execute(SQL_JOIN_DELETE, &[]).await?;
    for (id, root) in entries {
        txn.execute(SQL_CERT, &[root, root]).await?;
        txn.execute(SQL_ENTRY, &[id, &"Device", &1i64, &1i64, &1i64, &1i16])
            .await?;
        txn.execute(SQL_JOIN, &[id, root]).await?;
    }
    txn.execute(SQL_ENTRIES_DELETE, &[]).await?;
    txn.execute(SQL_CERTS_DELETE, &[]).await?;
    txn.execute(SQL_META_DELETE, &[&no]).await?;
    txn.commit().await
}

#[tokio::test]
#[ignore = "set RAUTHY_MDS_TEST_PG_URL; creates and removes an isolated test schema"]
async fn postgres_replacement_replay_and_revocation_regressions() {
    let url = std::env::var("RAUTHY_MDS_TEST_PG_URL").expect("RAUTHY_MDS_TEST_PG_URL");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let schema = format!("mds_test_{}", uuid::Uuid::new_v4().simple());
    client.batch_execute(&format!("CREATE SCHEMA {schema}; SET search_path TO {schema}; CREATE TABLE passkeys (id TEXT PRIMARY KEY);")).await.unwrap();
    client
        .batch_execute(include_str!(
            "../../../../migrations/postgres/V30__fido_mds.sql"
        ))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../../../migrations/postgres/V34__fido_mds_verification.sql"
        ))
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO fido_mds_metadata(current_blob_no,next_update) VALUES (9999,$1)",
            &[&(NOW + 86400)],
        )
        .await
        .unwrap();
    pg_replace(
        &mut client,
        1,
        &[1; 32],
        &[(A, b"old"), (B, b"revoked")],
        NOW + 3600,
    )
    .await
    .unwrap();
    client
        .execute(
            "INSERT INTO passkeys(id,aaguid) VALUES ('kept',$1),('revoked',$2)",
            &[&A, &B],
        )
        .await
        .unwrap();
    pg_replace(&mut client, 2, &[2; 32], &[(A, b"new")], NOW + 7200)
        .await
        .unwrap();
    assert!(
        pg_replace(&mut client, 1, &[1; 32], &[(B, b"bad")], NOW + 7200)
            .await
            .is_err()
    );
    assert!(
        pg_replace(&mut client, 2, &[3; 32], &[(B, b"bad")], NOW + 7200)
            .await
            .is_err()
    );
    pg_replace(&mut client, 2, &[2; 32], &[(A, b"new")], NOW + 10800)
        .await
        .unwrap();
    let metadata = client
        .query_one(
            "SELECT current_blob_no,verified_until FROM fido_mds_metadata",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(metadata.get::<_, i64>(0), 2);
    assert_eq!(metadata.get::<_, i64>(1), NOW + 10800);
    let roots = client
        .query("SELECT cert_der FROM fido_mds_certs", &[])
        .await
        .unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].get::<_, Vec<u8>>(0), b"new");
    let revoked = client
        .query_one("SELECT aaguid FROM passkeys WHERE id='revoked'", &[])
        .await
        .unwrap();
    let kept = client
        .query_one("SELECT aaguid FROM passkeys WHERE id='kept'", &[])
        .await
        .unwrap();
    assert_eq!(revoked.get::<_, Option<Vec<u8>>>(0), None);
    assert_eq!(kept.get::<_, Option<Vec<u8>>>(0).as_deref(), Some(A));
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    drop(client);
    driver.await.unwrap().unwrap();
}

#[test]
fn embedded_seed_replaces_legacy_or_older_but_preserves_newer_withdrawals() {
    let dataset = MdsDataset {
        blob_no: 2,
        next_update_ts: NOW,
        entries: vec![],
        certs: vec![],
        signed: SignedBlob {
            jwt: String::new(),
            crls: vec![],
        },
        blob_hash: vec![2; 32],
        verified_until: NOW - 1,
        embedded: true,
    };
    let mut metadata = MdsMetadata {
        current_blob_no: 9999,
        ..Default::default()
    };
    assert!(should_seed(&metadata, &dataset));
    metadata = MdsMetadata {
        current_blob_no: 1,
        next_update: NOW - 100,
        blob_hash: vec![1; 32],
        verified_until: NOW - 100,
    };
    assert!(should_seed(&metadata, &dataset));
    metadata.current_blob_no = 3;
    assert!(!should_seed(&metadata, &dataset));
    metadata.current_blob_no = 2;
    assert!(!should_seed(&metadata, &dataset)); // changed same-number payload
    metadata.blob_hash = vec![2; 32];
    assert!(should_seed(&metadata, &dataset));
    metadata.verified_until = NOW + 1;
    assert!(!should_seed(&metadata, &dataset)); // keep fresher evidence
}

#[test]
fn stale_snapshots_still_prevent_rollback_and_cache_keys_track_evidence() {
    let mut connection = sqlite();
    sqlite_replace(&mut connection, 2, &[2; 32], &[], NOW - 86400).unwrap();
    assert!(sqlite_replace(&mut connection, 1, &[1; 32], &[(A, b"resurrected")], NOW).is_err());
    let mut metadata = MdsMetadata {
        current_blob_no: 2,
        next_update: NOW,
        blob_hash: vec![2; 32],
        verified_until: NOW - 86400,
    };
    assert!(metadata.has_verified_snapshot());
    assert!(!metadata.is_current(NOW));
    let old = metadata.cache_tag();
    metadata.verified_until = NOW + 3600;
    assert_ne!(old, metadata.cache_tag());
    metadata.blob_hash.clear();
    assert!(!metadata.has_verified_snapshot());
}

#[tokio::test]
#[ignore = "requires RAUTHY_MDS_TEST_BLOB and live public GlobalSign CRLs"]
async fn official_prepared_asset_seeds_after_bundled_evidence_expires() {
    let bytes = std::fs::read(std::env::var("RAUTHY_MDS_TEST_BLOB").unwrap()).unwrap();
    let current = MdsDataset::from_jwt(std::str::from_utf8(&bytes).unwrap().trim())
        .await
        .unwrap();
    let asset = current.serialize().unwrap();
    // At two weeks after evidence expiry the public import fails, but the release-only seed
    // rechecks signatures/revocation at its issuer-signed historical time and remains usable.
    assert!(
        MdsDataset::from_signed(
            current.signed.clone(),
            current.verified_until + 14 * 86400,
            false
        )
        .is_err()
    );
    let embedded = MdsDataset::from_embedded(&asset).unwrap();
    assert!(embedded.embedded);
    assert_eq!(current.blob_hash, embedded.blob_hash);
    assert_eq!(current.entries, embedded.entries);
    assert_eq!(current.certs, embedded.certs);
    assert_eq!(current.verified_until, embedded.verified_until);
}
