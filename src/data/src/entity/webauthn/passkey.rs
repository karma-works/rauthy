use crate::database::{Cache, DB};
use crate::entity::password::PasswordPolicy;
use crate::entity::shared_devices::SharedDeviceMember;
use crate::entity::users::User;
use crate::fido_mds::mds_entry::MdsEntrySimple;
use crate::rauthy_config::RauthyConfig;
use chrono::Utc;
use hiqlite::{Params, params};
use rauthy_api_types::users::{PasskeyKind, PasskeyResponse};
use rauthy_common::constants::IDX_WEBAUTHN;
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::ops::Add;
use tracing::error;
use webauthn_rs::prelude::{CredentialID, Passkey, Uuid};

/// The message of the `NotFound` for a credential that is not (or no longer) registered.
/// `api::users::post_webauthn_auth_finish_login` matches on it.
pub const UNKNOWN_CREDENTIAL: &str = "Unknown Credential";

const SQL_FIND_BY_CRED_ID: &str = "SELECT * FROM passkeys WHERE credential_id = $1";
const SQL_SET_RESIDENT_KEY: &str =
    "UPDATE passkeys SET resident_key = true WHERE user_id = $1 AND name = $2";

/// `Ok(None)` is an unknown credential, which the UI handles. A database error must not look
/// like one, so the user is not sent to the recovery for a passkey that still works.
fn rk_lookup_result(
    res: Result<Option<PasskeyEntity>, ErrorResponse>,
) -> Result<PasskeyEntity, ErrorResponse> {
    match res {
        Ok(Some(pk)) => Ok(pk),
        Ok(None) => Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            UNKNOWN_CREDENTIAL,
        )),
        Err(err) => {
            error!(?err, "Looking up a discoverable credential");
            let typ = match err.error {
                ErrorResponseType::Connection
                | ErrorResponseType::DatabaseIo
                | ErrorResponseType::ServiceUnavailable => ErrorResponseType::ServiceUnavailable,
                _ => ErrorResponseType::Internal,
            };
            Err(ErrorResponse::new(
                typ,
                "Database error during the passkey lookup",
            ))
        }
    }
}

/// Whether a passkey used in a discoverable login still needs `resident_key = true`.
#[inline]
pub fn needs_rk_heal(resident_key: Option<bool>) -> bool {
    resident_key != Some(true)
}

#[derive(Clone, Deserialize, Serialize, FromPgRow)]
pub struct PasskeyEntity {
    pub user_id: String,
    pub name: String,
    pub passkey_user_id: String,
    pub passkey: String,
    pub credential_id: Vec<u8>,
    pub registered: i64,
    pub last_used: i64,
    pub user_verified: Option<bool>,
    pub resident_key: Option<bool>,
    pub aaguid: Option<Vec<u8>>,
    /// `PasskeyKind` as string, reported by the browser during the registration
    pub kind: Option<String>,
}

impl Debug for PasskeyEntity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let aaguid = self.aaguid.as_deref().map(hex::encode).unwrap_or_default();
        write!(
            f,
            "PasskeyEntity {{ user_id: {}, name: {}, passkey_user_id: {}, passkey: <hidden>, \
        credential_id: <hidden>, registered: {}, last_used: {}, user_verified: {:?}, \
        resident_key: {:?}, aaguid: {}, kind: {:?} }}",
            self.user_id,
            self.name,
            self.passkey_user_id,
            self.registered,
            self.last_used,
            self.user_verified,
            self.resident_key,
            aaguid,
            self.kind,
        )
    }
}

// CRUD
impl PasskeyEntity {
    /// If the `User` is `Some(_)`, a `User::save()` will be included in the `txn`
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        user_id: String,
        user: Option<User>,
        passkey_user_id: Uuid,
        name: String,
        pk: Passkey,
        user_verified: bool,
        resident_key: Option<bool>,
        aaguid: Option<Vec<u8>>,
        kind: Option<PasskeyKind>,
    ) -> Result<(), ErrorResponse> {
        // json, because bincode does not support deserialize from any, which would be the case here
        let passkey = serde_json::to_string(&pk)?;
        let now = Utc::now().timestamp();

        let entity = Self {
            user_id,
            name,
            passkey_user_id: passkey_user_id.to_string(),
            passkey,
            credential_id: pk.cred_id().to_vec(),
            registered: now,
            last_used: now,
            user_verified: Some(user_verified),
            resident_key,
            aaguid,
            kind: kind.map(|k| k.as_str().to_string()),
        };

        let user_email = user.as_ref().map(|u| u.email.clone());
        let client = DB::hql();

        let sql = r#"
INSERT INTO passkeys (
    user_id, name, passkey_user_id, passkey, credential_id, registered, last_used, user_verified,
    resident_key, aaguid, kind
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#;

        if is_hiqlite() {
            let mut txn = Vec::with_capacity(2);

            if let Some(user) = user {
                debug_assert!(user.webauthn_user_id.is_some());
                user.save_txn_append(&mut txn);
            }

            txn.push((
                sql,
                params!(
                    &entity.user_id,
                    entity.name,
                    entity.passkey_user_id,
                    entity.passkey,
                    entity.credential_id,
                    now,
                    now,
                    entity.user_verified,
                    entity.resident_key,
                    entity.aaguid,
                    entity.kind
                ),
            ));

            client.txn(txn).await?;
        } else {
            let mut cl = DB::pg().await?;
            let txn = cl.transaction().await?;

            if let Some(user) = user {
                debug_assert!(user.webauthn_user_id.is_some());
                user.save_txn(&txn).await?;
            }
            DB::pg_txn_append(
                &txn,
                sql,
                &[
                    &entity.user_id,
                    &entity.name,
                    &entity.passkey_user_id,
                    &entity.passkey,
                    &entity.credential_id,
                    &now,
                    &now,
                    &entity.user_verified,
                    &entity.resident_key,
                    &entity.aaguid,
                    &entity.kind,
                ],
            )
            .await?;

            txn.commit().await?;
        }

        if let Some(email) = user_email {
            User::invalidate_cache(&entity.user_id, &email).await?;
        }
        client
            .delete(Cache::Webauthn, Self::cache_idx_user(&entity.user_id))
            .await?;
        client
            .delete(
                Cache::Webauthn,
                Self::cache_idx_user_with_uv(&entity.user_id),
            )
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_creds(&entity.user_id))
            .await?;

        Ok(())
    }

    pub async fn count_for_user(user_id: String) -> Result<i64, ErrorResponse> {
        let sql = "SELECT COUNT (*) AS count FROM passkeys WHERE user_id = $1";
        let count: i64 = if is_hiqlite() {
            DB::hql()
                .query_raw_one(sql, params!(user_id))
                .await?
                .get("count")
        } else {
            DB::pg_query_one_row(sql, &[&user_id]).await?.get("count")
        };

        Ok(count)
    }

    pub async fn delete(user_id: String, name: String) -> Result<(), ErrorResponse> {
        // if we delete a passkey, we must check if this is the last existing one for the user
        let pk_count = Self::count_for_user(user_id.clone()).await?;

        let mut user_to_save: Option<User> = None;
        let mut user_email: Option<String> = None;

        if pk_count < 2 {
            let mut user = User::find(user_id.clone()).await?;
            user.webauthn_user_id = None;

            // We need to check against the current password policy
            // if the password should expire again.
            let policy = PasswordPolicy::find().await?;
            if let Some(valid_days) = policy.valid_days {
                if user.password.is_some() {
                    user.password_expires = Some(
                        Utc::now()
                            .add(chrono::Duration::days(valid_days as i64))
                            .timestamp(),
                    );
                } else {
                    user.password_expires = None;
                }
            }

            user_email = Some(user.email.clone());
            user_to_save = Some(user);
        }

        if is_hiqlite() {
            let mut txn = Vec::with_capacity(2);

            Self::delete_by_id_name_append(user_id.clone(), name.clone(), &mut txn);
            if let Some(user) = user_to_save {
                user.save_txn_append(&mut txn);
            }

            DB::hql().txn(txn).await?;
        } else {
            let mut cl = DB::pg().await?;
            let txn = cl.transaction().await?;

            Self::delete_by_id_name(&user_id, &name, &txn).await?;
            if let Some(user) = user_to_save {
                user.save_txn(&txn).await?;
            }

            txn.commit().await?;
        }

        let was_last = user_email.is_some();
        Self::clear_caches_by_id_name(&user_id, user_email, &name).await?;
        if was_last {
            SharedDeviceMember::delete_pins_for_user(&user_id).await?;
        }

        Ok(())
    }

    /// MUST call `PasskeyEntity::clear_caches_by_id_name()` after txn commit!
    async fn delete_by_id_name(
        user_id: &str,
        name: &str,
        txn: &deadpool_postgres::Transaction<'_>,
    ) -> Result<(), ErrorResponse> {
        DB::pg_txn_append(
            txn,
            "DELETE FROM passkeys WHERE user_id = $1 AND name = $2",
            &[&user_id, &name],
        )
        .await?;
        Ok(())
    }

    /// MUST call `PasskeyEntity::clear_caches_by_id_name()` after txn commit!
    fn delete_by_id_name_append(user_id: String, name: String, txn: &mut Vec<(&str, Params)>) {
        txn.push((
            "DELETE FROM passkeys WHERE user_id = $1 AND name = $2",
            params!(user_id, name),
        ));
    }

    async fn clear_caches_by_id_name(
        user_id: &str,
        user_email: Option<String>,
        name: &str,
    ) -> Result<(), ErrorResponse> {
        let client = DB::hql();

        if let Some(email) = user_email {
            User::invalidate_cache(user_id, &email).await?;
        }

        client
            .delete(Cache::Webauthn, Self::cache_idx_single(user_id, name))
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_user(user_id))
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_user_with_uv(user_id))
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_creds(user_id))
            .await?;

        Ok(())
    }

    pub async fn find(user_id: &str, name: &str) -> Result<Self, ErrorResponse> {
        let idx = Self::cache_idx_single(user_id, name);
        let client = DB::hql();

        if let Some(slf) = client.get(Cache::Webauthn, &idx).await? {
            return Ok(slf);
        }

        let sql = "SELECT * FROM passkeys WHERE user_id = $1 AND name = $2";
        let slf = if is_hiqlite() {
            client.query_as_one(sql, params!(user_id, name)).await?
        } else {
            DB::pg_query_one(sql, &[&user_id, &name]).await?
        };

        let ttl = Some(RauthyConfig::get().vars.webauthn.req_exp.as_secs() as i64);
        client.put(Cache::Webauthn, idx, &slf, ttl).await?;

        Ok(slf)
    }

    /// Finds the passkey for a credential the browser offered in a discoverable login.
    ///
    /// Deliberately not limited to `resident_key = true`: browsers do not always report the
    /// `credProps` during the registration (iOS Chrome, Android), so the column can be `NULL`
    /// for a discoverable credential. A credential offered without an allow list is
    /// discoverable. Which user it belongs to is still checked against the User Handle in
    /// `authenticate_rk::auth_finish_discover`.
    pub async fn find_rk_by_cred_id(cred_id: &[u8]) -> Result<Self, ErrorResponse> {
        let res = if is_hiqlite() {
            DB::hql()
                .query_as_optional(SQL_FIND_BY_CRED_ID, params!(cred_id))
                .await
                .map_err(ErrorResponse::from)
        } else {
            DB::pg_query_opt(SQL_FIND_BY_CRED_ID, &[&cred_id]).await
        };
        rk_lookup_result(res)
    }

    /// Self-healing for passkeys that were stored without `resident_key = true`, after they
    /// were just used in a discoverable login.
    pub async fn set_resident_key(&mut self) -> Result<(), ErrorResponse> {
        if is_hiqlite() {
            DB::hql()
                .execute(SQL_SET_RESIDENT_KEY, params!(&self.user_id, &self.name))
                .await?;
        } else {
            DB::pg_execute(SQL_SET_RESIDENT_KEY, &[&self.user_id, &self.name]).await?;
        }
        self.resident_key = Some(true);

        let client = DB::hql();
        client
            .delete(
                Cache::Webauthn,
                Self::cache_idx_single(&self.user_id, &self.name),
            )
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_user(&self.user_id))
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_user_with_uv(&self.user_id))
            .await?;

        Ok(())
    }

    pub async fn find_cred_ids_for_user(user_id: &str) -> Result<Vec<CredentialID>, ErrorResponse> {
        let idx = Self::cache_idx_creds(user_id);
        let client = DB::hql();

        let opt: Option<Vec<Vec<u8>>> = client.get(Cache::Webauthn, &idx).await?;
        if let Some(bytes) = opt {
            return Ok(bytes.into_iter().map(CredentialID::from).collect());
        }

        let sql = "SELECT credential_id FROM passkeys WHERE user_id = $1";
        let creds = if is_hiqlite() {
            client
                .query_raw(sql, params!(user_id))
                .await?
                .into_iter()
                .map(|mut r| r.get::<Vec<u8>>("credential_id"))
                .collect::<Vec<_>>()
        } else {
            DB::pg_query_rows(sql, &[&user_id], 2)
                .await?
                .into_iter()
                .map(|r| r.get::<_, Vec<u8>>("credential_id"))
                .collect::<Vec<_>>()
        };

        let ttl = Some(RauthyConfig::get().vars.webauthn.req_exp.as_secs() as i64);
        client.put(Cache::Webauthn, idx, &creds, ttl).await?;

        Ok(creds.into_iter().map(CredentialID::from).collect())
    }

    pub async fn find_for_user(user_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let idx = Self::cache_idx_user(user_id);
        let client = DB::hql();

        if let Some(slf) = client.get(Cache::Webauthn, &idx).await? {
            return Ok(slf);
        }

        let sql = "SELECT * FROM passkeys WHERE user_id = $1";
        let pks = if is_hiqlite() {
            client.query_as(sql, params!(user_id)).await?
        } else {
            DB::pg_query(sql, &[&user_id], 2).await?
        };

        let ttl = Some(RauthyConfig::get().vars.webauthn.req_exp.as_secs() as i64);
        client.put(Cache::Webauthn, idx, &pks, ttl).await?;

        Ok(pks)
    }

    pub async fn find_for_user_with_uv(user_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let idx = Self::cache_idx_user_with_uv(user_id);
        let client = DB::hql();

        if let Some(slf) = client.get(Cache::Webauthn, &idx).await? {
            return Ok(slf);
        }

        let sql = "SELECT * FROM passkeys WHERE user_id = $1 AND user_verified = true";
        let pks = if is_hiqlite() {
            client.query_as(sql, params!(user_id)).await?
        } else {
            DB::pg_query(sql, &[&user_id], 2).await?
        };

        let ttl = Some(RauthyConfig::get().vars.webauthn.req_exp.as_secs() as i64);
        client.put(Cache::Webauthn, idx, &pks, ttl).await?;

        Ok(pks)
    }

    pub async fn find_for_user_with_details(
        user_id: &str,
    ) -> Result<Vec<PasskeyResponse>, ErrorResponse> {
        let passkeys = Self::find_for_user(user_id).await?;
        let mut res = Vec::with_capacity(passkeys.len());

        for pk in passkeys {
            let mut resp = PasskeyResponse {
                name: pk.name,
                registered: pk.registered,
                last_used: pk.last_used,
                user_verified: pk.user_verified,
                resident_key: pk.resident_key,
                aaguid: pk.aaguid.as_deref().map(format_aaguid),
                description: None,
                kind: pk.kind.as_deref().and_then(PasskeyKind::parse),
            };

            if let Some(aaguid) = &pk.aaguid {
                // Doing these as single lookups instead of DB joins is fast. All the MDS entries
                // are cached.
                // Device descriptions are optional. Expired metadata must not prevent users
                // from viewing or managing their passkeys; policy checks still fail closed.
                if let Ok(mds) = MdsEntrySimple::find(aaguid).await {
                    resp.description = Some(mds.description);
                }
            }

            res.push(resp);
        }

        Ok(res)
    }

    pub async fn update_passkey(&self) -> Result<(), ErrorResponse> {
        let client = DB::hql();

        let sql = r#"
UPDATE passkeys
SET passkey = $1, last_used = $2
WHERE user_id = $3 AND name = $4"#;

        if is_hiqlite() {
            client
                .execute(
                    sql,
                    params!(&self.passkey, self.last_used, &self.user_id, &self.name),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[&self.passkey, &self.last_used, &self.user_id, &self.name],
            )
            .await?;
        }

        let ttl = Some(RauthyConfig::get().vars.webauthn.req_exp.as_secs() as i64);
        client
            .put(
                Cache::Webauthn,
                Self::cache_idx_single(&self.user_id, &self.name),
                self,
                ttl,
            )
            .await?;

        client
            .delete(Cache::Webauthn, Self::cache_idx_user(&self.user_id))
            .await?;
        client
            .delete(Cache::Webauthn, Self::cache_idx_user_with_uv(&self.user_id))
            .await?;

        Ok(())
    }
}

impl PasskeyEntity {
    #[inline]
    pub fn get_pk(&self) -> Passkey {
        // Passkeys cannot be serialized with bincode -> no support for deserialize from any
        serde_json::from_str(&self.passkey).unwrap()
    }

    /// Index for a single passkey for a user
    #[inline]
    fn cache_idx_single(user_id: &str, name: &str) -> String {
        format!("{IDX_WEBAUTHN}{user_id}{name}")
    }

    /// Index for all passkeys a user has
    #[inline]
    fn cache_idx_user(user_id: &str) -> String {
        format!("{IDX_WEBAUTHN}{user_id}")
    }

    /// Index for all passkeys a user has
    #[inline]
    fn cache_idx_user_with_uv(user_id: &str) -> String {
        format!("{IDX_WEBAUTHN}_UV_{user_id}",)
    }

    /// Index for credentials for a user
    #[inline]
    fn cache_idx_creds(user_id: &str) -> String {
        format!("{IDX_WEBAUTHN}{user_id}_creds")
    }
}

/// Formats a 16-byte AAGUID as a canonical lowercase UUID-style string
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Any other length is returned as plain hex.
fn format_aaguid(aaguid: &[u8]) -> String {
    let hex = hex::encode(aaguid);
    if hex.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    } else {
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, OptionalExtension};

    /// The filter before the fix: credentials registered without `credProps` were never found.
    const SQL_FIND_BY_CRED_ID_OLD: &str =
        "SELECT * FROM passkeys WHERE credential_id = $1 AND resident_key = true";

    /// An in-memory SQLite with the real Hiqlite migrations, so the statements run against the
    /// production schema.
    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();

        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations/hiqlite");
        let mut files = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "sql"))
            .collect::<Vec<_>>();
        let num = |p: &std::path::PathBuf| -> u32 {
            let name = p.file_name().unwrap().to_str().unwrap();
            name.split('_').next().unwrap().parse().unwrap()
        };
        files.sort_by_key(num);
        for f in files {
            let sql = std::fs::read_to_string(&f).unwrap();
            conn.execute_batch(&sql)
                .unwrap_or_else(|err| panic!("migration {f:?}: {err}"));
        }
        // the test rows have no `users` row, and a migration enables the FK checks
        conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();

        for (name, cred_id, rk) in [
            ("rk-null", b"cred-null".as_slice(), None),
            ("rk-false", b"cred-false".as_slice(), Some(false)),
            ("rk-true", b"cred-true".as_slice(), Some(true)),
        ] {
            conn.execute(
                "INSERT INTO passkeys (user_id, name, passkey_user_id, passkey, credential_id, \
                registered, last_used, user_verified, resident_key) \
                VALUES ('user-1', ?1, 'pk-user-1', '{}', ?2, 1, 1, 1, ?3)",
                rusqlite::params![name, cred_id, rk],
            )
            .unwrap();
        }
        conn
    }

    fn find(conn: &Connection, sql: &str, cred_id: &[u8]) -> Option<(String, Option<bool>)> {
        conn.query_row(sql, [cred_id], |row| {
            Ok((
                row.get::<_, String>("name")?,
                row.get::<_, Option<bool>>("resident_key")?,
            ))
        })
        .optional()
        .unwrap()
    }

    #[test]
    fn test_find_by_cred_id_ignores_resident_key() {
        let conn = db();
        for (cred_id, name, rk) in [
            (b"cred-null".as_slice(), "rk-null", None),
            (b"cred-false".as_slice(), "rk-false", Some(false)),
            (b"cred-true".as_slice(), "rk-true", Some(true)),
        ] {
            assert_eq!(
                find(&conn, SQL_FIND_BY_CRED_ID, cred_id),
                Some((name.to_string(), rk)),
            );
        }
        assert_eq!(find(&conn, SQL_FIND_BY_CRED_ID, b"cred-unknown"), None);

        // the incident of 2026-10-24: the old filter missed NULL and false
        assert_eq!(find(&conn, SQL_FIND_BY_CRED_ID_OLD, b"cred-null"), None);
        assert_eq!(find(&conn, SQL_FIND_BY_CRED_ID_OLD, b"cred-false"), None);
    }

    #[test]
    fn test_set_resident_key_heals_only_the_one_passkey() {
        let conn = db();
        for name in ["rk-null", "rk-false", "rk-true"] {
            let changed = conn
                .execute(SQL_SET_RESIDENT_KEY, ["user-1", name])
                .unwrap();
            assert_eq!(changed, 1);
        }
        for cred_id in [b"cred-null".as_slice(), b"cred-false", b"cred-true"] {
            let (_, rk) = find(&conn, SQL_FIND_BY_CRED_ID, cred_id).unwrap();
            assert_eq!(rk, Some(true));
        }
        assert_eq!(
            conn.execute(SQL_SET_RESIDENT_KEY, ["user-2", "rk-null"])
                .unwrap(),
            0
        );
    }

    #[test]
    fn test_needs_rk_heal() {
        assert!(needs_rk_heal(None));
        assert!(needs_rk_heal(Some(false)));
        assert!(!needs_rk_heal(Some(true)));
    }

    fn entity() -> PasskeyEntity {
        PasskeyEntity {
            user_id: "user-1".to_string(),
            name: "rk-null".to_string(),
            passkey_user_id: "pk-user-1".to_string(),
            passkey: "{}".to_string(),
            credential_id: b"cred-null".to_vec(),
            registered: 1,
            last_used: 1,
            user_verified: Some(true),
            resident_key: None,
            aaguid: None,
            kind: None,
        }
    }

    #[test]
    fn test_rk_lookup_result_separates_errors() {
        let pk = rk_lookup_result(Ok(Some(entity()))).unwrap();
        assert_eq!(pk.name, "rk-null");

        let err = rk_lookup_result(Ok(None)).unwrap_err();
        assert_eq!(err.error, ErrorResponseType::NotFound);
        assert_eq!(err.message, UNKNOWN_CREDENTIAL);

        for typ in [
            ErrorResponseType::Connection,
            ErrorResponseType::DatabaseIo,
            ErrorResponseType::ServiceUnavailable,
        ] {
            let err = rk_lookup_result(Err(ErrorResponse::new(typ, "pool timeout"))).unwrap_err();
            assert_eq!(err.error, ErrorResponseType::ServiceUnavailable);
            assert_ne!(err.message, UNKNOWN_CREDENTIAL);
        }

        // never a NotFound for a database error, so the UI does not send people to recovery
        for typ in [ErrorResponseType::Database, ErrorResponseType::NotFound] {
            let err = rk_lookup_result(Err(ErrorResponse::new(typ, "x"))).unwrap_err();
            assert_eq!(err.error, ErrorResponseType::Internal);
        }
    }
}
