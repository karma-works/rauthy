//! Registered shared devices (practice PCs) and the PIN sign-in on them
//! (`shared_devices.enable`), see `arztagent/SPEC-PHASE2-PIN-AM-PRAXIS-PC.md`.
//!
//! - A `SharedDevicePractice` groups devices and the people (`SharedDeviceMember`) who may sign in
//!   on them with a PIN. It is maintained by an external backend through the admin API. Rauthy has
//!   no notion of practice roles itself.
//! - A `SharedDevice` is registered from a `SharedDeviceRegistration` by its user, with a fresh
//!   passkey and in the same browser. The browser gets the cookie `COOKIE_SHARED_DEVICE` (random
//!   token, only its hash is stored) and keeps a non-extractable ECDSA P-256 key, which signs a
//!   `SharedDeviceChallenge` for each PIN login.
//! - PINs are unique within a practice. Only `HMAC-SHA256(derived key, practice_id, pin)` is stored,
//!   together with the ID of the encryption key.
//! - `PIN_MAX_FAILURES` wrong PINs within `PIN_FAILURE_WINDOW_SECS` lock a device until a member
//!   signs in on it with a passkey, see `SharedDevice::reserve_attempt` and
//!   `on_shared_device_login`. A correct PIN does not reset the count.
//! - A session from a PIN login only serves the login flow, see `is_pin_session_path`.
//! - Sessions from a registered browser carry `Session::shared_device_id`. Each login on a device
//!   ends all other sessions there, see `Session::set_authenticated`.

use crate::api_cookie::ApiCookie;
use crate::database::{Cache, DB};
use crate::email::notification::{send_email_shared_device_ip, send_email_shared_device_locked};
use crate::entity::clients::Client;
use crate::entity::refresh_tokens::RefreshToken;
use crate::entity::sessions::MfaMethod;
use crate::entity::users::User;
use crate::rauthy_config::RauthyConfig;
use actix_web::HttpRequest;
use actix_web::cookie::{Cookie, SameSite};
use chrono::Utc;
use cryptr::EncKeys;
use hiqlite::macros::{FromRow, params};
use rauthy_common::constants::CACHE_TTL_APP;
use rauthy_common::is_hiqlite;
use rauthy_common::utils::{get_rand, get_rand_between};
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use reqwest::Url;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use tracing::{error, info, warn};
use uuid::Uuid;

pub const COOKIE_SHARED_DEVICE: &str = "rauthy_shared_device";
/// Browsers cap cookies at 400 days. The cookie is renewed with each PIN login.
pub const COOKIE_MAX_AGE_SECS: i64 = 400 * 24 * 3600;

/// Wrong PINs on a device within `PIN_FAILURE_WINDOW_SECS` before it is locked. A correct PIN
/// does not reset them, so that a member cannot keep guessing colleagues' PINs between own logins.
pub const PIN_MAX_FAILURES: i64 = 5;
pub const PIN_FAILURE_WINDOW_SECS: i64 = 24 * 3600;
/// A session on a shared device never lives longer than one shift
pub const SESSION_MAX_SECS: i64 = 10 * 3600;
pub const IDLE_TIMEOUT_MIN: i64 = 120;
pub const IDLE_TIMEOUT_MAX: i64 = 900;
pub const IDLE_TIMEOUT_DEFAULT: i64 = 300;
pub const REGISTRATION_LIFETIME_SECS: i64 = 600;
const CHALLENGE_LIFETIME_SECS: i64 = 60;
/// Device events are only kept for security purposes
pub const EVENTS_RETENTION_DAYS: i64 = 90;
/// PIN generations per user and practice in 24 h
const PIN_GENERATE_MAX_PER_DAY: i64 = 10;
/// At most one warning mail about a changed IP per device in this time
const IP_WARN_INTERVAL_SECS: i64 = 24 * 3600;

const IDX_PRACTICE: &str = "shared_dev_practice_";
const IDX_REGISTRATION: &str = "shared_dev_reg_";
const IDX_CHALLENGE: &str = "shared_dev_chal_";
const IDX_PIN_GENERATED: &str = "shared_dev_pin_gen_";

#[inline]
pub fn is_enabled() -> bool {
    RauthyConfig::get().vars.shared_devices.enable
}

/// `404` unless `shared_devices.enable`
pub fn check_enabled() -> Result<(), ErrorResponse> {
    if is_enabled() {
        Ok(())
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "Shared devices are not enabled",
        ))
    }
}

/// Only these clients accept a PIN login, see `shared_devices.client_ids`.
#[inline]
pub fn is_pin_client(client_id: &str) -> bool {
    is_enabled()
        && RauthyConfig::get()
            .vars
            .shared_devices
            .client_ids
            .iter()
            .any(|c| c == client_id)
}

/// IPv4 exact, IPv6 per /64, so that privacy extensions do not trigger a warning each day.
fn same_network(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => a == b,
        (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => a.segments()[..4] == b.segments()[..4],
        _ => a == b,
    }
}

// ##################################################################################
// Practices
// ##################################################################################

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, FromPgRow)]
pub struct SharedDevicePractice {
    pub id: String,
    pub name: String,
    pub idle_timeout: i64,
    /// Comma-separated user IDs that get warnings for this practice
    pub notify_user_ids: String,
    pub risk_ack_by: Option<String>,
    pub risk_ack_at: Option<i64>,
    pub created: i64,
    pub updated: i64,
}

impl SharedDevicePractice {
    fn cache_idx(id: &str) -> String {
        format!("{IDX_PRACTICE}{id}")
    }

    pub async fn upsert(
        id: String,
        name: String,
        idle_timeout: i64,
        notify_user_ids: Vec<String>,
    ) -> Result<Self, ErrorResponse> {
        let now = Utc::now().timestamp();
        let notify = notify_user_ids.join(",");
        let sql = r#"
INSERT INTO shared_device_practices
    (id, name, idle_timeout, notify_user_ids, risk_ack_by, risk_ack_at, created, updated)
VALUES ($1, $2, $3, $4, NULL, NULL, $5, $5)
ON CONFLICT(id) DO UPDATE SET name = $2, idle_timeout = $3, notify_user_ids = $4, updated = $5"#;

        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(id.clone(), name, idle_timeout, notify, now))
                .await?;
        } else {
            DB::pg_execute(sql, &[&id, &name, &idle_timeout, &notify, &now]).await?;
        }
        DB::hql().delete(Cache::App, Self::cache_idx(&id)).await?;
        Self::find(&id).await
    }

    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        let client = DB::hql();
        if let Some(slf) = client.get(Cache::App, Self::cache_idx(id)).await? {
            return Ok(slf);
        }

        let sql = "SELECT * FROM shared_device_practices WHERE id = $1";
        let slf: Self = if is_hiqlite() {
            client.query_map_one(sql, params!(id.to_string())).await?
        } else {
            DB::pg_query_one(sql, &[&id]).await?
        };

        client
            .put(Cache::App, Self::cache_idx(id), &slf, CACHE_TTL_APP)
            .await?;
        Ok(slf)
    }

    /// Deletes the practice with all its devices, members and events, and ends the sessions on
    /// its devices.
    pub async fn delete(id: &str) -> Result<(), ErrorResponse> {
        for device in SharedDevice::find_for_practice(id).await? {
            end_device_sessions(&device.id, None).await?;
        }

        let sql_events = "DELETE FROM shared_device_events WHERE practice_id = $1";
        let sql = "DELETE FROM shared_device_practices WHERE id = $1";
        if is_hiqlite() {
            DB::hql()
                .txn([
                    (sql_events, params!(id.to_string())),
                    (sql, params!(id.to_string())),
                ])
                .await?;
        } else {
            let mut cl = DB::pg().await?;
            let txn = cl.transaction().await?;
            DB::pg_txn_append(&txn, sql_events, &[&id]).await?;
            DB::pg_txn_append(&txn, sql, &[&id]).await?;
            txn.commit().await?;
        }
        DB::hql().delete(Cache::App, Self::cache_idx(id)).await?;
        Ok(())
    }

    /// Records who confirmed the residual risk notice with the first device of the practice.
    pub async fn ack_risk(&self, user_id: &str) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        let sql = "UPDATE shared_device_practices SET risk_ack_by = $1, risk_ack_at = $2 \
            WHERE id = $3";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(user_id.to_string(), now, self.id.clone()))
                .await?;
        } else {
            DB::pg_execute(sql, &[&user_id, &now, &self.id]).await?;
        }
        DB::hql()
            .delete(Cache::App, Self::cache_idx(&self.id))
            .await?;
        Ok(())
    }

    pub fn notify_user_ids(&self) -> Vec<&str> {
        self.notify_user_ids
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect()
    }

    /// Clamped to `IDLE_TIMEOUT_MIN..=IDLE_TIMEOUT_MAX`, for rows written by hand
    pub fn idle_timeout(&self) -> i64 {
        self.idle_timeout.clamp(IDLE_TIMEOUT_MIN, IDLE_TIMEOUT_MAX)
    }

    async fn notify_users(&self) -> Vec<User> {
        let mut users = Vec::new();
        for id in self.notify_user_ids() {
            match User::find(id.to_string()).await {
                Ok(user) => users.push(user),
                Err(err) => warn!(practice_id = self.id, ?err, "notify user not found"),
            }
        }
        users
    }
}

// ##################################################################################
// Members and PINs
// ##################################################################################

#[derive(Clone, Serialize, Deserialize, FromRow, FromPgRow)]
pub struct SharedDeviceMember {
    pub practice_id: String,
    pub user_id: String,
    pub pin_hmac: Option<Vec<u8>>,
    pub pin_key_id: Option<String>,
    pub pin_created: Option<i64>,
    pub created: i64,
}

impl Debug for SharedDeviceMember {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SharedDeviceMember {{ practice_id: {}, user_id: {}, pin_hmac: <hidden>, \
            pin_key_id: {:?}, pin_created: {:?}, created: {} }}",
            self.practice_id, self.user_id, self.pin_key_id, self.pin_created, self.created,
        )
    }
}

/// A member with the name of its practice, for the user's own account page
#[derive(Debug, Serialize, Deserialize, FromRow, FromPgRow)]
pub struct SharedDeviceMembership {
    pub practice_id: String,
    pub practice_name: String,
    pub pin_created: Option<i64>,
}

/// 4 digits without trivial patterns like `0000`, `1234`, `4321` or `1212`.
pub fn is_trivial_pin(pin: &str) -> bool {
    let d: Vec<i8> = pin.bytes().map(|b| b as i8 - b'0' as i8).collect();
    if d.len() != 4 {
        return true;
    }
    let all_same = d.iter().all(|x| *x == d[0]);
    let ascending = d.windows(2).all(|w| w[1] - w[0] == 1);
    let descending = d.windows(2).all(|w| w[0] - w[1] == 1);
    let abab = d[0] == d[2] && d[1] == d[3];
    all_same || ascending || descending || abab
}

pub fn is_valid_pin_format(pin: &str) -> bool {
    pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit())
}

/// The encryption key is not used directly, but a key derived from it for this purpose only.
/// The practice is part of the input, so that equal PINs of different practices differ.
fn pin_hmac(enc_key: &[u8], practice_id: &str, pin: &str) -> Vec<u8> {
    let key = hmac_sha256::HMAC::mac(b"rauthy-shared-device-pins", enc_key);
    let mut input = Vec::with_capacity(practice_id.len() + 1 + pin.len());
    input.extend_from_slice(practice_id.as_bytes());
    input.push(0);
    input.extend_from_slice(pin.as_bytes());
    hmac_sha256::HMAC::mac(input, key).to_vec()
}

impl SharedDeviceMember {
    /// Adds a member, does nothing if it exists already.
    pub async fn add(practice_id: &str, user_id: &str) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        let sql = r#"
INSERT INTO shared_device_members
    (practice_id, user_id, pin_hmac, pin_key_id, pin_created, created)
VALUES ($1, $2, NULL, NULL, NULL, $3)
ON CONFLICT(practice_id, user_id) DO NOTHING"#;
        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(practice_id.to_string(), user_id.to_string(), now),
                )
                .await?;
        } else {
            DB::pg_execute(sql, &[&practice_id, &user_id, &now]).await?;
        }
        Ok(())
    }

    /// Removes a member with its PIN and ends its sessions on the devices of the practice.
    pub async fn remove(practice_id: &str, user_id: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM shared_device_members WHERE practice_id = $1 AND user_id = $2";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(practice_id.to_string(), user_id.to_string()))
                .await?;
        } else {
            DB::pg_execute(sql, &[&practice_id, &user_id]).await?;
        }
        end_user_sessions_in_practice(practice_id, user_id, false).await
    }

    pub async fn find(practice_id: &str, user_id: &str) -> Result<Option<Self>, ErrorResponse> {
        let sql = "SELECT * FROM shared_device_members WHERE practice_id = $1 AND user_id = $2";
        let res = if is_hiqlite() {
            DB::hql()
                .query_map_optional(sql, params!(practice_id.to_string(), user_id.to_string()))
                .await?
        } else {
            DB::pg_query_opt(sql, &[&practice_id, &user_id]).await?
        };
        Ok(res)
    }

    pub async fn find_for_practice(practice_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let sql = "SELECT * FROM shared_device_members WHERE practice_id = $1 ORDER BY created";
        let res = if is_hiqlite() {
            DB::hql()
                .query_map(sql, params!(practice_id.to_string()))
                .await?
        } else {
            DB::pg_query(sql, &[&practice_id], 8).await?
        };
        Ok(res)
    }

    pub async fn find_for_user(
        user_id: &str,
    ) -> Result<Vec<SharedDeviceMembership>, ErrorResponse> {
        let sql = r#"
SELECT m.practice_id AS practice_id, p.name AS practice_name, m.pin_created AS pin_created
FROM shared_device_members m
JOIN shared_device_practices p ON p.id = m.practice_id
WHERE m.user_id = $1
ORDER BY p.name"#;
        let res = if is_hiqlite() {
            DB::hql()
                .query_map(sql, params!(user_id.to_string()))
                .await?
        } else {
            DB::pg_query(sql, &[&user_id], 1).await?
        };
        Ok(res)
    }

    /// A PIN only works after a passkey. When the last passkey of an account is gone, e.g. by a
    /// sign-in reset, its PINs are deleted and its PIN sessions end.
    pub async fn delete_pins_for_user(user_id: &str) -> Result<(), ErrorResponse> {
        let sql = "UPDATE shared_device_members \
            SET pin_hmac = NULL, pin_key_id = NULL, pin_created = NULL WHERE user_id = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(user_id.to_string())).await?;
        } else {
            DB::pg_execute(sql, &[&user_id]).await?;
        }

        let sql = "DELETE FROM sessions WHERE user_id = $1 AND mfa_method = 'pin' RETURNING id";
        let sids: Vec<String> = if is_hiqlite() {
            let rows = DB::hql()
                .execute_returning(sql, params!(user_id.to_string()))
                .await?;
            let mut ids = Vec::with_capacity(rows.len());
            for row in rows {
                ids.push(row?.get("id"));
            }
            ids
        } else {
            DB::pg_query_rows(sql, &[&user_id], 1)
                .await?
                .into_iter()
                .map(|row| row.get("id"))
                .collect()
        };
        end_sessions(sids).await
    }

    /// Fails with `TooManyRequests` after `PIN_GENERATE_MAX_PER_DAY` new PINs in 24 h.
    pub async fn check_generate_limit(
        practice_id: &str,
        user_id: &str,
    ) -> Result<(), ErrorResponse> {
        let idx = format!("{IDX_PIN_GENERATED}{practice_id}_{user_id}");
        let now = Utc::now().timestamp();
        let window = 24 * 3600;
        let mut stamps: Vec<i64> = DB::hql().get(Cache::App, &idx).await?.unwrap_or_default();
        stamps.retain(|ts| *ts > now - window);
        if stamps.len() as i64 >= PIN_GENERATE_MAX_PER_DAY {
            return Err(ErrorResponse::new(
                ErrorResponseType::TooManyRequests(now + window),
                "Too many new PINs within 24 hours",
            ));
        }
        stamps.push(now);
        DB::hql()
            .put(Cache::App, idx, &stamps, Some(window))
            .await?;
        Ok(())
    }

    /// Sets a new random PIN that is free within the practice and returns it in plain text. It
    /// is never stored or shown again. Ends the member's PIN sessions on the practice's devices,
    /// so that a PIN that became known cannot be used any further.
    pub async fn generate_pin(practice_id: &str, user_id: &str) -> Result<String, ErrorResponse> {
        let enc_keys = EncKeys::get_static();
        let key_id = enc_keys.enc_key_active.clone();
        let key = enc_keys.get_key(&key_id)?;
        let other_keys = Self::pin_key_ids(practice_id).await?;
        let now = Utc::now().timestamp();

        for _ in 0..64 {
            let pin = format!("{:04}", get_rand_between(0, 10_000));
            if is_trivial_pin(&pin) {
                continue;
            }
            if Self::find_by_pin_with_keys(practice_id, &pin, &other_keys)
                .await?
                .is_some()
            {
                continue;
            }

            let hmac = pin_hmac(key, practice_id, &pin);
            let sql = "UPDATE shared_device_members \
                SET pin_hmac = $1, pin_key_id = $2, pin_created = $3 \
                WHERE practice_id = $4 AND user_id = $5";
            // The unique index `shared_device_members_pin` rejects a PIN that has been taken
            // concurrently. Try another one then.
            let res = if is_hiqlite() {
                DB::hql()
                    .execute(
                        sql,
                        params!(
                            hmac,
                            key_id.clone(),
                            now,
                            practice_id.to_string(),
                            user_id.to_string()
                        ),
                    )
                    .await
                    .map_err(ErrorResponse::from)
            } else {
                DB::pg_execute(sql, &[&hmac, &key_id, &now, &practice_id, &user_id]).await
            };
            match res {
                Ok(1) => {
                    end_user_sessions_in_practice(practice_id, user_id, true).await?;
                    return Ok(pin);
                }
                Ok(_) => {
                    return Err(ErrorResponse::new(
                        ErrorResponseType::NotFound,
                        "Not a member of this practice",
                    ));
                }
                Err(err) => {
                    warn!(?err, "PIN collision, trying another one");
                    continue;
                }
            }
        }

        Err(ErrorResponse::new(
            ErrorResponseType::Internal,
            "Could not find a free PIN",
        ))
    }

    async fn pin_key_ids(practice_id: &str) -> Result<Vec<String>, ErrorResponse> {
        let sql = "SELECT DISTINCT pin_key_id FROM shared_device_members \
            WHERE practice_id = $1 AND pin_key_id IS NOT NULL";
        let ids = if is_hiqlite() {
            DB::hql()
                .query_raw(sql, params!(practice_id.to_string()))
                .await?
                .into_iter()
                .map(|mut row| row.get("pin_key_id"))
                .collect()
        } else {
            DB::pg_query_rows(sql, &[&practice_id], 1)
                .await?
                .into_iter()
                .map(|row| row.get("pin_key_id"))
                .collect()
        };
        Ok(ids)
    }

    /// The user ID the PIN belongs to in this practice
    pub async fn find_by_pin(
        practice_id: &str,
        pin: &str,
    ) -> Result<Option<String>, ErrorResponse> {
        let key_ids = Self::pin_key_ids(practice_id).await?;
        Self::find_by_pin_with_keys(practice_id, pin, &key_ids).await
    }

    async fn find_by_pin_with_keys(
        practice_id: &str,
        pin: &str,
        key_ids: &[String],
    ) -> Result<Option<String>, ErrorResponse> {
        let sql = "SELECT user_id FROM shared_device_members \
            WHERE practice_id = $1 AND pin_hmac = $2 AND pin_key_id = $3";
        for key_id in key_ids {
            let Ok(key) = EncKeys::get_static().get_key(key_id) else {
                error!(key_id, "encryption key for shared device PINs is missing");
                continue;
            };
            let hmac = pin_hmac(key, practice_id, pin);
            let user_id: Option<String> = if is_hiqlite() {
                DB::hql()
                    .query_raw(sql, params!(practice_id.to_string(), hmac, key_id.clone()))
                    .await?
                    .into_iter()
                    .next()
                    .map(|mut row| row.get("user_id"))
            } else {
                DB::pg_query_rows(sql, &[&practice_id, &hmac, &key_id], 1)
                    .await?
                    .into_iter()
                    .next()
                    .map(|row| row.get("user_id"))
            };
            if user_id.is_some() {
                return Ok(user_id);
            }
        }
        Ok(None)
    }
}

// ##################################################################################
// Devices
// ##################################################################################

#[derive(Clone, Serialize, Deserialize, FromRow, FromPgRow)]
pub struct SharedDevice {
    pub id: String,
    pub practice_id: String,
    pub label: String,
    pub token_hash: Vec<u8>,
    /// Uncompressed SEC1 point of the browser's ECDSA P-256 key
    pub public_key: Vec<u8>,
    pub ip_registered: String,
    pub ip_lock: bool,
    pub failed_pins: i64,
    /// Start of the window of `failed_pins`
    pub failed_since: Option<i64>,
    pub locked_at: Option<i64>,
    pub created_by: String,
    pub created: i64,
    pub last_seen: i64,
    pub last_seen_ip: Option<String>,
    pub ip_warned: Option<i64>,
}

impl Debug for SharedDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SharedDevice {{ id: {}, practice_id: {}, label: {}, token_hash: <hidden>, \
            ip_registered: {}, ip_lock: {}, failed_pins: {}, locked_at: {:?} }}",
            self.id,
            self.practice_id,
            self.label,
            self.ip_registered,
            self.ip_lock,
            self.failed_pins,
            self.locked_at,
        )
    }
}

fn hash_token(token: &str) -> Vec<u8> {
    hmac_sha256::Hash::hash(token.as_bytes()).to_vec()
}

/// Checks that `key` is an uncompressed P-256 point. The signature check itself proves that the
/// key is usable.
pub fn validate_public_key(key: &[u8]) -> Result<(), ErrorResponse> {
    if key.len() == 65 && key[0] == 0x04 {
        Ok(())
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "`public_key` must be an uncompressed P-256 point",
        ))
    }
}

/// Verifies an ECDSA P-256 / SHA-256 signature in the IEEE P1363 format WebCrypto produces.
pub fn verify_signature(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(msg, signature)
        .is_ok()
}

impl SharedDevice {
    /// Returns the new device and the plain token for its cookie.
    pub async fn create(
        practice_id: String,
        label: String,
        public_key: Vec<u8>,
        ip: String,
        created_by: String,
    ) -> Result<(Self, String), ErrorResponse> {
        let token = get_rand(64);
        let now = Utc::now().timestamp();
        let slf = Self {
            // ArztAgent expects a UUID in `aa_shared_device`.
            id: Uuid::new_v4().to_string(),
            practice_id,
            label,
            token_hash: hash_token(&token),
            public_key,
            ip_registered: ip.clone(),
            ip_lock: false,
            failed_pins: 0,
            failed_since: None,
            locked_at: None,
            created_by,
            created: now,
            last_seen: now,
            last_seen_ip: Some(ip),
            ip_warned: None,
        };

        let sql = r#"
INSERT INTO shared_devices
    (id, practice_id, label, token_hash, public_key, ip_registered, ip_lock, failed_pins,
    failed_since, locked_at, created_by, created, last_seen, last_seen_ip, ip_warned)
VALUES ($1, $2, $3, $4, $5, $6, $7, 0, NULL, NULL, $8, $9, $9, $10, NULL)"#;
        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(
                        slf.id.clone(),
                        slf.practice_id.clone(),
                        slf.label.clone(),
                        slf.token_hash.clone(),
                        slf.public_key.clone(),
                        slf.ip_registered.clone(),
                        false,
                        slf.created_by.clone(),
                        now,
                        slf.last_seen_ip.clone()
                    ),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[
                    &slf.id,
                    &slf.practice_id,
                    &slf.label,
                    &slf.token_hash,
                    &slf.public_key,
                    &slf.ip_registered,
                    &false,
                    &slf.created_by,
                    &now,
                    &slf.last_seen_ip,
                ],
            )
            .await?;
        }

        Ok((slf, token))
    }

    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        let sql = "SELECT * FROM shared_devices WHERE id = $1";
        let slf = if is_hiqlite() {
            DB::hql()
                .query_map_one(sql, params!(id.to_string()))
                .await?
        } else {
            DB::pg_query_one(sql, &[&id]).await?
        };
        Ok(slf)
    }

    async fn find_by_token(token: &str) -> Result<Option<Self>, ErrorResponse> {
        let hash = hash_token(token);
        let sql = "SELECT * FROM shared_devices WHERE token_hash = $1";
        let res = if is_hiqlite() {
            DB::hql().query_map_optional(sql, params!(hash)).await?
        } else {
            DB::pg_query_opt(sql, &[&hash]).await?
        };
        Ok(res)
    }

    /// The registered device of this browser, if any. Always `None` unless
    /// `shared_devices.enable`.
    pub async fn from_req(req: &HttpRequest) -> Result<Option<Self>, ErrorResponse> {
        if !is_enabled() {
            return Ok(None);
        }
        match Self::token_from_req(req) {
            Some(token) => Self::find_by_token(&token).await,
            None => Ok(None),
        }
    }

    pub fn token_from_req(req: &HttpRequest) -> Option<String> {
        ApiCookie::from_req(req, COOKIE_SHARED_DEVICE).filter(|t| t.len() == 64)
    }

    pub fn build_cookie<'a>(token: &str) -> Cookie<'a> {
        // `Lax`, so that a link from another site still shows the PIN login. The cookie alone
        // proves nothing without the device key.
        ApiCookie::build_with_same_site(
            COOKIE_SHARED_DEVICE,
            token,
            COOKIE_MAX_AGE_SECS,
            SameSite::Lax,
        )
    }

    pub async fn find_for_practice(practice_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let sql = "SELECT * FROM shared_devices WHERE practice_id = $1 ORDER BY created";
        let res = if is_hiqlite() {
            DB::hql()
                .query_map(sql, params!(practice_id.to_string()))
                .await?
        } else {
            DB::pg_query(sql, &[&practice_id], 4).await?
        };
        Ok(res)
    }

    /// Revokes the device and ends all sessions on it.
    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM shared_devices WHERE id = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(self.id.clone())).await?;
        } else {
            DB::pg_execute(sql, &[&self.id]).await?;
        }
        end_device_sessions(&self.id, None).await
    }

    pub async fn update(&self, label: &str, ip_lock: bool) -> Result<(), ErrorResponse> {
        let sql = "UPDATE shared_devices SET label = $1, ip_lock = $2 WHERE id = $3";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(label.to_string(), ip_lock, self.id.clone()))
                .await?;
        } else {
            DB::pg_execute(sql, &[&label, &ip_lock, &self.id]).await?;
        }
        Ok(())
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked_at.is_some()
    }

    /// Counts an attempt as a failure before the PIN is checked, atomically, so that parallel
    /// requests can never test more PINs than allowed. `None` if the device is locked. Failures
    /// older than `PIN_FAILURE_WINDOW_SECS` start over. A correct PIN gives its attempt back with
    /// `release_attempt`.
    pub async fn reserve_attempt(&self, ip: &str) -> Result<Option<i64>, ErrorResponse> {
        let now = Utc::now().timestamp();
        let sql = "UPDATE shared_devices SET \
            failed_pins = CASE WHEN failed_since IS NULL OR failed_since < $1 THEN 1 \
                ELSE failed_pins + 1 END, \
            failed_since = CASE WHEN failed_since IS NULL OR failed_since < $1 THEN $2 \
                ELSE failed_since END \
            WHERE id = $3 AND locked_at IS NULL RETURNING failed_pins";
        let window_start = now - PIN_FAILURE_WINDOW_SECS;
        let count: Option<i64> = if is_hiqlite() {
            let mut rows = DB::hql()
                .execute_returning(sql, params!(window_start, now, self.id.clone()))
                .await?;
            match rows.pop() {
                Some(row) => Some(row?.get("failed_pins")),
                None => None,
            }
        } else {
            DB::pg_query_rows(sql, &[&window_start, &now, &self.id], 1)
                .await?
                .pop()
                .map(|row| row.get("failed_pins"))
        };

        match count {
            // a burst of parallel requests beyond the limit locks right away
            Some(c) if c > PIN_MAX_FAILURES => {
                self.lock(ip).await?;
                Ok(None)
            }
            c => Ok(c),
        }
    }

    /// After a correct PIN: gives the reserved attempt back and refreshes `last_seen`. Earlier
    /// failures stay counted.
    pub async fn release_attempt(&self, ip: &str) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        let sql = "UPDATE shared_devices SET \
            failed_pins = CASE WHEN failed_pins > 0 THEN failed_pins - 1 ELSE 0 END, \
            last_seen = $1, last_seen_ip = $2 WHERE id = $3";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(now, ip.to_string(), self.id.clone()))
                .await?;
        } else {
            DB::pg_execute(sql, &[&now, &ip, &self.id]).await?;
        }
        Ok(())
    }

    /// A wrong PIN after `reserve_attempt` returned `count`. Locks the device at
    /// `PIN_MAX_FAILURES`.
    pub async fn wrong_pin(&self, count: i64, ip: &str) -> Result<(), ErrorResponse> {
        SharedDeviceEvent::create(
            &self.practice_id,
            Some(&self.id),
            None,
            SharedDeviceEventKind::PinFailed,
            Some(ip),
        )
        .await?;
        if count >= PIN_MAX_FAILURES {
            self.lock(ip).await?;
        }
        Ok(())
    }

    /// Only the request that actually locks sends the event and the E-Mails.
    async fn lock(&self, ip: &str) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        let sql = "UPDATE shared_devices SET locked_at = $1 WHERE id = $2 AND locked_at IS NULL";
        let rows = if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(now, self.id.clone()))
                .await?
        } else {
            DB::pg_execute(sql, &[&now, &self.id]).await?
        };
        if rows != 1 {
            return Ok(());
        }

        warn!(
            device_id = self.id,
            "shared device locked after too many wrong PINs"
        );
        SharedDeviceEvent::create(
            &self.practice_id,
            Some(&self.id),
            None,
            SharedDeviceEventKind::Locked,
            Some(ip),
        )
        .await?;
        if let Ok(practice) = SharedDevicePractice::find(&self.practice_id).await {
            for user in practice.notify_users().await {
                send_email_shared_device_locked(&user, &self.label, &practice.name).await;
            }
        }
        Ok(())
    }

    async fn unlock(&self) -> Result<(), ErrorResponse> {
        let sql = "UPDATE shared_devices SET failed_pins = 0, failed_since = NULL, locked_at = NULL \
            WHERE id = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(self.id.clone())).await?;
        } else {
            DB::pg_execute(sql, &[&self.id]).await?;
        }
        Ok(())
    }

    /// `Err(Forbidden)` for a device with `ip_lock` that is used from another network. Otherwise,
    /// warns the practice once per `IP_WARN_INTERVAL_SECS` if the network has changed.
    pub async fn check_ip(&self, ip: &str) -> Result<(), ErrorResponse> {
        if same_network(ip, &self.ip_registered) {
            return Ok(());
        }

        if self.ip_lock {
            SharedDeviceEvent::create(
                &self.practice_id,
                Some(&self.id),
                None,
                SharedDeviceEventKind::IpBlocked,
                Some(ip),
            )
            .await?;
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "This device may only be used from the network it has been registered in",
            ));
        }

        let now = Utc::now().timestamp();
        // Only one request wins the update, so that concurrent logins send a single mail.
        let sql = "UPDATE shared_devices SET ip_warned = $1 \
            WHERE id = $2 AND (ip_warned IS NULL OR ip_warned < $3)";
        let rows = if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(now, self.id.clone(), now - IP_WARN_INTERVAL_SECS),
                )
                .await?
        } else {
            DB::pg_execute(sql, &[&now, &self.id, &(now - IP_WARN_INTERVAL_SECS)]).await?
        };
        if rows == 1 {
            SharedDeviceEvent::create(
                &self.practice_id,
                Some(&self.id),
                None,
                SharedDeviceEventKind::IpChanged,
                Some(ip),
            )
            .await?;
            if let Ok(practice) = SharedDevicePractice::find(&self.practice_id).await {
                for user in practice.notify_users().await {
                    send_email_shared_device_ip(&user, &self.label, &practice.name, ip).await;
                }
            }
        }
        Ok(())
    }
}

/// The content of `<template id="tpl_shared_device">` on the login page. Template contents are
/// inserted unescaped, so `<`, `>` and `&` in names are JSON-escaped.
pub fn template_json(label: &str, practice: &str, locked: bool, pin: bool) -> String {
    let json = serde_json::json!({
        "label": label,
        "practice": practice,
        "locked": locked,
        "pin": pin,
    })
    .to_string();
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// A link back from the registration page must lead to a client that accepts a PIN, so that the
/// page can never be used to redirect elsewhere.
pub async fn validate_return_uri(uri: &str) -> Result<(), ErrorResponse> {
    let err = || {
        ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "`return_uri` must have the origin of a redirect URI of a PIN client",
        )
    };
    let url = Url::parse(uri).map_err(|_| err())?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(err());
    }
    for client_id in &RauthyConfig::get().vars.shared_devices.client_ids {
        let Ok(client) = Client::find(client_id.clone()).await else {
            continue;
        };
        for redirect in client.get_redirect_uris() {
            if let Ok(r) = Url::parse(redirect.trim_end_matches('*'))
                && r.origin() == url.origin()
            {
                return Ok(());
            }
        }
    }
    Err(err())
}

/// Ends all sessions on a device except `keep_sid`, together with their refresh tokens.
pub async fn end_device_sessions(
    device_id: &str,
    keep_sid: Option<&str>,
) -> Result<(), ErrorResponse> {
    let keep = keep_sid.unwrap_or_default();
    let sql = "DELETE FROM sessions WHERE shared_device_id = $1 AND id != $2 RETURNING id";
    let sids: Vec<String> = if is_hiqlite() {
        let rows = DB::hql()
            .execute_returning(sql, params!(device_id.to_string(), keep.to_string()))
            .await?;
        let mut ids = Vec::with_capacity(rows.len());
        for row in rows {
            ids.push(row?.get("id"));
        }
        ids
    } else {
        DB::pg_query_rows(sql, &[&device_id, &keep], 1)
            .await?
            .into_iter()
            .map(|row| row.get("id"))
            .collect()
    };
    end_sessions(sids).await
}

/// Ends the sessions of a user on all devices of a practice, or only those from a PIN login.
async fn end_user_sessions_in_practice(
    practice_id: &str,
    user_id: &str,
    only_pin: bool,
) -> Result<(), ErrorResponse> {
    let sql = if only_pin {
        "DELETE FROM sessions WHERE user_id = $1 AND mfa_method = 'pin' AND shared_device_id IN \
        (SELECT id FROM shared_devices WHERE practice_id = $2) RETURNING id"
    } else {
        "DELETE FROM sessions WHERE user_id = $1 AND shared_device_id IN \
        (SELECT id FROM shared_devices WHERE practice_id = $2) RETURNING id"
    };
    let sids: Vec<String> = if is_hiqlite() {
        let rows = DB::hql()
            .execute_returning(sql, params!(user_id.to_string(), practice_id.to_string()))
            .await?;
        let mut ids = Vec::with_capacity(rows.len());
        for row in rows {
            ids.push(row?.get("id"));
        }
        ids
    } else {
        DB::pg_query_rows(sql, &[&user_id, &practice_id], 1)
            .await?
            .into_iter()
            .map(|row| row.get("id"))
            .collect()
    };
    end_sessions(sids).await
}

async fn end_sessions(sids: Vec<String>) -> Result<(), ErrorResponse> {
    for sid in sids {
        DB::hql().delete(Cache::Session, sid.clone()).await?;
        RefreshToken::delete_by_sid(sid).await?;
    }
    Ok(())
}

/// Called after a session with `shared_device_id` has been bound to a user. Ends all other
/// sessions on the device. A passkey login of a member unlocks the device.
pub async fn on_shared_device_login(
    device_id: &str,
    session_id: &str,
    user_id: &str,
    method: MfaMethod,
    ip: Option<&str>,
) -> Result<(), ErrorResponse> {
    end_device_sessions(device_id, Some(session_id)).await?;
    // A session that has been bound to another user before keeps no tokens of that user.
    let sql = "DELETE FROM refresh_tokens WHERE session_id = $1 AND user_id != $2";
    if is_hiqlite() {
        DB::hql()
            .execute(sql, params!(session_id.to_string(), user_id.to_string()))
            .await?;
    } else {
        DB::pg_execute(sql, &[&session_id, &user_id]).await?;
    }

    let device = match SharedDevice::find(device_id).await {
        Ok(d) => d,
        // revoked in the meantime, the session will not work anymore anyway
        Err(_) => return Ok(()),
    };

    let kind = match method {
        MfaMethod::Pin => SharedDeviceEventKind::PinLogin,
        MfaMethod::WebAuthn => SharedDeviceEventKind::PasskeyLogin,
        _ => SharedDeviceEventKind::OtherLogin,
    };
    SharedDeviceEvent::create(
        &device.practice_id,
        Some(device_id),
        Some(user_id),
        kind,
        ip,
    )
    .await?;

    if method == MfaMethod::WebAuthn
        && (device.is_locked() || device.failed_pins > 0)
        && SharedDeviceMember::find(&device.practice_id, user_id)
            .await?
            .is_some()
    {
        device.unlock().await?;
        info!(device_id, user_id, "shared device unlocked with a passkey");
        if device.is_locked() {
            SharedDeviceEvent::create(
                &device.practice_id,
                Some(device_id),
                Some(user_id),
                SharedDeviceEventKind::Unlocked,
                ip,
            )
            .await?;
        }
    }

    Ok(())
}

/// A session from a PIN login only serves the login flow itself. It must never open the account
/// or admin pages, approve a device code, or change the account, because a PIN is no MFA.
pub fn is_pin_session_path(path: &str) -> bool {
    matches!(
        path,
        "/auth/v1/oidc/authorize"
            | "/auth/v1/oidc/authorize/pin"
            | "/auth/v1/dev/authorize"
            | "/auth/v1/oidc/callback"
            | "/auth/v1/oidc/logout"
            | "/auth/v1/tos/accept"
            | "/auth/v1/tos/deny"
    )
}

/// The idle timeout of the practice of the device, if the device still exists
pub async fn idle_timeout_for_device(device_id: &str) -> Option<i64> {
    let device = SharedDevice::find(device_id).await.ok()?;
    let practice = SharedDevicePractice::find(&device.practice_id).await.ok()?;
    Some(practice.idle_timeout())
}

// ##################################################################################
// Registrations and challenges (cache only)
// ##################################################################################

/// Created by the admin API, redeemed by `user_id` in the browser that becomes the device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedDeviceRegistration {
    pub id: String,
    pub practice_id: String,
    pub user_id: String,
    pub label: String,
    pub return_uri: Option<String>,
    pub exp: i64,
}

impl SharedDeviceRegistration {
    fn cache_idx(id: &str) -> String {
        format!("{IDX_REGISTRATION}{id}")
    }

    pub async fn create(
        practice_id: String,
        user_id: String,
        label: String,
        return_uri: Option<String>,
    ) -> Result<Self, ErrorResponse> {
        let slf = Self {
            id: get_rand(48),
            practice_id,
            user_id,
            label,
            return_uri,
            exp: Utc::now().timestamp() + REGISTRATION_LIFETIME_SECS,
        };
        DB::hql()
            .put(
                Cache::App,
                Self::cache_idx(&slf.id),
                &slf,
                Some(REGISTRATION_LIFETIME_SECS + 1),
            )
            .await?;
        Ok(slf)
    }

    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        let slf: Option<Self> = DB::hql().get(Cache::App, Self::cache_idx(id)).await?;
        match slf {
            Some(slf) if slf.exp >= Utc::now().timestamp() => Ok(slf),
            _ => Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "The registration does not exist or has expired",
            )),
        }
    }

    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::App, Self::cache_idx(&self.id))
            .await?;
        Ok(())
    }
}

/// Signed by the device's browser key for each PIN login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedDeviceChallenge {
    pub id: String,
    pub device_id: String,
    pub challenge: String,
    pub exp: i64,
}

impl SharedDeviceChallenge {
    fn cache_idx(id: &str) -> String {
        format!("{IDX_CHALLENGE}{id}")
    }

    pub async fn create(device_id: String) -> Result<Self, ErrorResponse> {
        let slf = Self {
            id: get_rand(32),
            device_id,
            challenge: get_rand(48),
            exp: Utc::now().timestamp() + CHALLENGE_LIFETIME_SECS,
        };
        DB::hql()
            .put(
                Cache::App,
                Self::cache_idx(&slf.id),
                &slf,
                Some(CHALLENGE_LIFETIME_SECS + 1),
            )
            .await?;
        Ok(slf)
    }

    /// Single use: the challenge is removed atomically, no matter if it is valid.
    pub async fn take(id: &str, device_id: &str) -> Result<Self, ErrorResponse> {
        let slf: Option<Self> = DB::hql()
            .get_remove(Cache::App, Self::cache_idx(id))
            .await?;
        match slf {
            Some(slf) if slf.exp >= Utc::now().timestamp() && slf.device_id == device_id => Ok(slf),
            _ => Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Invalid device challenge",
            )),
        }
    }
}

// ##################################################################################
// Events
// ##################################################################################

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedDeviceEventKind {
    Registered,
    Revoked,
    PinLogin,
    PasskeyLogin,
    OtherLogin,
    PinFailed,
    Locked,
    Unlocked,
    IpChanged,
    IpBlocked,
    PinChanged,
}

impl SharedDeviceEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Revoked => "revoked",
            Self::PinLogin => "pin_login",
            Self::PasskeyLogin => "passkey_login",
            Self::OtherLogin => "other_login",
            Self::PinFailed => "pin_failed",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
            Self::IpChanged => "ip_changed",
            Self::IpBlocked => "ip_blocked",
            Self::PinChanged => "pin_changed",
        }
    }
}

/// Security log per practice. No User-Agent, no location. Kept `EVENTS_RETENTION_DAYS`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, FromPgRow)]
pub struct SharedDeviceEvent {
    pub id: String,
    pub practice_id: String,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub kind: String,
    pub ip: Option<String>,
    pub created: i64,
}

impl SharedDeviceEvent {
    pub async fn create(
        practice_id: &str,
        device_id: Option<&str>,
        user_id: Option<&str>,
        kind: SharedDeviceEventKind,
        ip: Option<&str>,
    ) -> Result<(), ErrorResponse> {
        let id = get_rand(24);
        let now = Utc::now().timestamp();
        let kind = kind.as_str();
        let sql = "INSERT INTO shared_device_events \
            (id, practice_id, device_id, user_id, kind, ip, created) \
            VALUES ($1, $2, $3, $4, $5, $6, $7)";
        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(
                        id,
                        practice_id.to_string(),
                        device_id.map(String::from),
                        user_id.map(String::from),
                        kind,
                        ip.map(String::from),
                        now
                    ),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[&id, &practice_id, &device_id, &user_id, &kind, &ip, &now],
            )
            .await?;
        }
        Ok(())
    }

    /// The newest events of a practice first
    pub async fn find_for_practice(
        practice_id: &str,
        limit: i64,
    ) -> Result<Vec<Self>, ErrorResponse> {
        let limit = limit.clamp(1, 1000);
        let sql = "SELECT * FROM shared_device_events WHERE practice_id = $1 \
            ORDER BY created DESC LIMIT $2";
        let res = if is_hiqlite() {
            DB::hql()
                .query_map(sql, params!(practice_id.to_string(), limit))
                .await?
        } else {
            DB::pg_query(sql, &[&practice_id, &limit], 64).await?
        };
        Ok(res)
    }

    pub async fn cleanup() -> Result<usize, ErrorResponse> {
        let threshold = Utc::now().timestamp() - EVENTS_RETENTION_DAYS * 24 * 3600;
        let sql = "DELETE FROM shared_device_events WHERE created < $1";
        let rows = if is_hiqlite() {
            DB::hql().execute(sql, params!(threshold)).await?
        } else {
            DB::pg_execute(sql, &[&threshold]).await?
        };
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trivial_pins() {
        for pin in [
            "0000", "1111", "1234", "6789", "0123", "4321", "3210", "1212", "9090",
        ] {
            assert!(is_trivial_pin(pin), "{pin}");
        }
        for pin in ["1357", "2468", "0815", "4711", "1122", "9182"] {
            assert!(!is_trivial_pin(pin), "{pin}");
        }
        assert!(is_trivial_pin("123"));
        assert!(is_trivial_pin("12345"));
    }

    #[test]
    fn test_pin_format() {
        assert!(is_valid_pin_format("0815"));
        assert!(!is_valid_pin_format("081"));
        assert!(!is_valid_pin_format("08155"));
        assert!(!is_valid_pin_format("08a5"));
        assert!(!is_valid_pin_format("٠٨١٥"));
    }

    #[test]
    fn test_pin_hmac_binds_practice() {
        let key = [7u8; 32];
        assert_eq!(pin_hmac(&key, "p1", "0815"), pin_hmac(&key, "p1", "0815"));
        assert_ne!(pin_hmac(&key, "p1", "0815"), pin_hmac(&key, "p2", "0815"));
        assert_ne!(pin_hmac(&key, "p1", "0815"), pin_hmac(&key, "p1", "4711"));
        // no ambiguity between practice and PIN
        assert_ne!(pin_hmac(&key, "p1", "10815"), pin_hmac(&key, "p11", "0815"));
    }

    #[test]
    fn test_template_json_is_escaped() {
        let json = template_json("</template><script>", "A & B", true, false);
        assert!(!json.contains('<') && !json.contains('>') && !json.contains('&'));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["label"], "</template><script>");
        assert_eq!(v["practice"], "A & B");
        assert_eq!(v["locked"], true);
        assert_eq!(v["pin"], false);
    }

    #[test]
    fn test_same_network() {
        assert!(same_network("10.0.0.1", "10.0.0.1"));
        assert!(!same_network("10.0.0.1", "10.0.0.2"));
        assert!(same_network("2001:db8:1:2:aaaa::1", "2001:db8:1:2:bbbb::2"));
        assert!(!same_network("2001:db8:1:2::1", "2001:db8:1:3::1"));
        assert!(!same_network("10.0.0.1", "2001:db8::1"));
    }

    #[test]
    fn test_signature_roundtrip() {
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let public = kp.public_key().as_ref().to_vec();
        validate_public_key(&public).unwrap();

        let sig = kp.sign(&rng, b"challenge").unwrap();
        assert!(verify_signature(&public, b"challenge", sig.as_ref()));
        assert!(!verify_signature(&public, b"other", sig.as_ref()));
        assert!(validate_public_key(&public[1..]).is_err());
    }
}
