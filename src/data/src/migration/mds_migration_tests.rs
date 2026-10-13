use super::*;
use crate::migration::inserts::FIDO_MDS_METADATA_INSERT;
use rusqlite::params;

const VERSION: i64 = 290;
const NEXT_UPDATE: i64 = 1_792_972_800;
const VERIFIED_UNTIL: i64 = 1_791_892_800;
const HASH: &[u8] = &[42; 32];

fn sqlite_metadata_table(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            "CREATE TABLE fido_mds_metadata (
        current_blob_no INTEGER PRIMARY KEY NOT NULL,
        next_update INTEGER NOT NULL,
        blob_hash BLOB NOT NULL,
        verified_until INTEGER NOT NULL
    ) STRICT",
        )
        .unwrap();
}

#[tokio::test]
async fn fido_mds_migration_sqlite_preserves_verified_state_and_defaults_legacy_columns() {
    for (has_hash, has_deadline) in [(false, false), (true, false), (false, true), (true, true)] {
        let source = rusqlite::Connection::open_in_memory().unwrap();
        source
            .execute_batch(
                "CREATE TABLE fido_mds_metadata (
            current_blob_no INTEGER PRIMARY KEY NOT NULL, next_update INTEGER NOT NULL
        ) STRICT",
            )
            .unwrap();
        if has_hash {
            source
                .execute_batch(
                    "ALTER TABLE fido_mds_metadata ADD blob_hash BLOB NOT NULL DEFAULT X''",
                )
                .unwrap();
        }
        if has_deadline {
            source
                .execute_batch(
                    "ALTER TABLE fido_mds_metadata ADD verified_until INTEGER NOT NULL DEFAULT 0",
                )
                .unwrap();
        }
        source
            .execute(
                "INSERT INTO fido_mds_metadata(current_blob_no,next_update) VALUES ($1,$2)",
                params![VERSION, NEXT_UPDATE],
            )
            .unwrap();
        if has_hash {
            source
                .execute("UPDATE fido_mds_metadata SET blob_hash=$1", params![HASH])
                .unwrap();
        }
        if has_deadline {
            source
                .execute(
                    "UPDATE fido_mds_metadata SET verified_until=$1",
                    params![VERIFIED_UNTIL],
                )
                .unwrap();
        }
        let query = fido_mds_metadata_query_sqlite(&source).unwrap();
        let metadata = query_sqlite::<MdsMetadata>(&source, query)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let verified = has_hash && has_deadline;
        assert_eq!(metadata.current_blob_no, VERSION);
        assert_eq!(metadata.next_update, NEXT_UPDATE);
        assert_eq!(
            metadata.blob_hash,
            if verified { HASH.to_vec() } else { vec![] }
        );
        assert_eq!(
            metadata.verified_until,
            if verified { VERIFIED_UNTIL } else { 0 }
        );

        let destination = rusqlite::Connection::open_in_memory().unwrap();
        sqlite_metadata_table(&destination);
        destination
            .execute(
                FIDO_MDS_METADATA_INSERT,
                params![
                    metadata.current_blob_no,
                    metadata.next_update,
                    metadata.blob_hash,
                    metadata.verified_until
                ],
            )
            .unwrap();
        let copied = query_sqlite::<MdsMetadata>(&destination, FIDO_MDS_METADATA_VERIFIED)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(copied.current_blob_no, metadata.current_blob_no);
        assert_eq!(copied.next_update, metadata.next_update);
        assert_eq!(copied.blob_hash, metadata.blob_hash);
        assert_eq!(copied.verified_until, metadata.verified_until);
    }
}

#[tokio::test]
#[ignore = "set RAUTHY_MDS_TEST_PG_URL; creates and removes an isolated test schema"]
async fn fido_mds_migration_postgres_preserves_verified_state_and_defaults_legacy_columns() {
    let url = std::env::var("RAUTHY_MDS_TEST_PG_URL").expect("RAUTHY_MDS_TEST_PG_URL");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let schema = format!("mds_migration_test_{}", uuid::Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    for (has_hash, has_deadline) in [(false, false), (true, false), (false, true), (true, true)] {
        client
            .batch_execute(
                "CREATE TABLE fido_mds_metadata (
            current_blob_no BIGINT PRIMARY KEY NOT NULL, next_update BIGINT NOT NULL
        )",
            )
            .await
            .unwrap();
        if has_hash {
            client
                .batch_execute(
                    "ALTER TABLE fido_mds_metadata ADD blob_hash BYTEA NOT NULL DEFAULT ''::bytea",
                )
                .await
                .unwrap();
        }
        if has_deadline {
            client
                .batch_execute(
                    "ALTER TABLE fido_mds_metadata ADD verified_until BIGINT NOT NULL DEFAULT 0",
                )
                .await
                .unwrap();
        }
        client
            .execute(
                "INSERT INTO fido_mds_metadata(current_blob_no,next_update) VALUES ($1,$2)",
                &[&VERSION, &NEXT_UPDATE],
            )
            .await
            .unwrap();
        if has_hash {
            client
                .execute("UPDATE fido_mds_metadata SET blob_hash=$1", &[&HASH])
                .await
                .unwrap();
        }
        if has_deadline {
            client
                .execute(
                    "UPDATE fido_mds_metadata SET verified_until=$1",
                    &[&VERIFIED_UNTIL],
                )
                .await
                .unwrap();
        }
        let query = fido_mds_metadata_query_pg(&client).await.unwrap();
        let metadata = MdsMetadata::from(client.query_one(query, &[]).await.unwrap());
        let verified = has_hash && has_deadline;
        assert_eq!(metadata.current_blob_no, VERSION);
        assert_eq!(metadata.next_update, NEXT_UPDATE);
        assert_eq!(
            metadata.blob_hash,
            if verified { HASH.to_vec() } else { vec![] }
        );
        assert_eq!(
            metadata.verified_until,
            if verified { VERIFIED_UNTIL } else { 0 }
        );

        client
            .batch_execute(
                "ALTER TABLE fido_mds_metadata RENAME TO fido_mds_source;
            CREATE TABLE fido_mds_metadata (
                current_blob_no BIGINT PRIMARY KEY NOT NULL, next_update BIGINT NOT NULL,
                blob_hash BYTEA NOT NULL, verified_until BIGINT NOT NULL
            )",
            )
            .await
            .unwrap();
        client
            .execute(
                FIDO_MDS_METADATA_INSERT,
                &[
                    &metadata.current_blob_no,
                    &metadata.next_update,
                    &metadata.blob_hash,
                    &metadata.verified_until,
                ],
            )
            .await
            .unwrap();
        let copied = MdsMetadata::from(
            client
                .query_one(FIDO_MDS_METADATA_VERIFIED, &[])
                .await
                .unwrap(),
        );
        assert_eq!(copied.current_blob_no, metadata.current_blob_no);
        assert_eq!(copied.next_update, metadata.next_update);
        assert_eq!(copied.blob_hash, metadata.blob_hash);
        assert_eq!(copied.verified_until, metadata.verified_until);
        client
            .batch_execute("DROP TABLE fido_mds_metadata; DROP TABLE fido_mds_source")
            .await
            .unwrap();
    }
    // Column discovery must resolve the same relation as SELECT, including search_path
    // fallback and a legacy table shadowing a newer table in a later schema.
    client
        .batch_execute(
            "CREATE TABLE fido_mds_metadata (
        current_blob_no BIGINT PRIMARY KEY NOT NULL, next_update BIGINT NOT NULL,
        blob_hash BYTEA NOT NULL, verified_until BIGINT NOT NULL
    )",
        )
        .await
        .unwrap();
    client
        .execute(
            FIDO_MDS_METADATA_INSERT,
            &[&VERSION, &NEXT_UPDATE, &HASH, &VERIFIED_UNTIL],
        )
        .await
        .unwrap();
    let first_schema = format!("{schema}_first");
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {first_schema}; SET search_path TO {first_schema}, {schema}"
        ))
        .await
        .unwrap();
    let query = fido_mds_metadata_query_pg(&client).await.unwrap();
    let fallback = MdsMetadata::from(client.query_one(query, &[]).await.unwrap());
    assert_eq!(fallback.blob_hash, HASH);
    assert_eq!(fallback.verified_until, VERIFIED_UNTIL);
    client
        .batch_execute(
            "CREATE TABLE fido_mds_metadata (
        current_blob_no BIGINT PRIMARY KEY NOT NULL, next_update BIGINT NOT NULL
    )",
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO fido_mds_metadata VALUES ($1,$2)",
            &[&(VERSION + 1), &NEXT_UPDATE],
        )
        .await
        .unwrap();
    let query = fido_mds_metadata_query_pg(&client).await.unwrap();
    let shadowed = MdsMetadata::from(client.query_one(query, &[]).await.unwrap());
    assert_eq!(shadowed.current_blob_no, VERSION + 1);
    assert!(shadowed.blob_hash.is_empty());
    assert_eq!(shadowed.verified_until, 0);
    client
        .batch_execute(&format!(
            "DROP SCHEMA {first_schema} CASCADE; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
    drop(client);
    driver.await.unwrap().unwrap();
}
