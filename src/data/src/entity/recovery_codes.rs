//! One-time recovery codes for passkey accounts (`webauthn.recovery_codes`).
//!
//! - Ten codes like `ABCD-EFGH-JKLM` (Crockford Base32, 60 random bits each). Only
//!   `HMAC-SHA256(encryption key, code)` is stored, together with the ID of the key, so that a key
//!   rotation keeps existing codes valid and a database dump alone does not allow a search.
//! - Redeeming is a public, two-step flow: E-Mail + code (`RecoveryChallenge::start`), then a
//!   code sent by E-Mail, entered in the same browser (`RecoveryChallenge::verify`). Only then a
//!   `MagicLinkUsage::PasskeyRecovery` link allows to register a new passkey.
//! - `RecoveryLock` blocks an IP after too many failed attempts (sliding 24 h window) and warns
//!   the account owner. Neither the response nor its timing reveals whether an account exists or
//!   a code was valid.

use crate::database::{Cache, DB};
use crate::entity::users::User;
use chrono::Utc;
use cryptr::EncKeys;
use hiqlite::params;
use rauthy_common::is_hiqlite;
use rauthy_common::utils::{get_rand, get_rand_between};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;

/// Crockford Base32: no I, L, O, U
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const CODES_COUNT: usize = 10;
const CODE_LEN: usize = 12;

/// Failed redeem attempts per account in `LOCK_WINDOW_SECS` before the user gets a warning
pub const WARN_FAILURES_ACCOUNT: usize = 5;
const LOCK_WINDOW_SECS: i64 = 24 * 3600;
/// Failed redeem attempts per IP (IPv6 per /64, any account) in `LOCK_WINDOW_SECS` before
/// redeeming from there is blocked
const LOCK_MAX_FAILURES_IP: usize = 20;
/// Code generations per user in `LOCK_WINDOW_SECS`
const GENERATE_MAX_PER_DAY: usize = 5;

/// The code sent by E-Mail during redeeming
const MAIL_CODE_DIGITS: usize = 8;
pub const MAIL_CODE_LIFETIME_SECS: i64 = 600;
const MAIL_CODE_MAX_ATTEMPTS: i64 = 3;

const IDX_LOCK: &str = "recovery_lock_";
const IDX_LOCK_IP: &str = "recovery_lock_ip_";
const IDX_GENERATED: &str = "recovery_gen_";
const IDX_CHALLENGE: &str = "recovery_challenge_";
const IDX_CHALLENGE_USER: &str = "recovery_challenge_user_";
const IDX_CHALLENGE_ATTEMPTS: &str = "recovery_challenge_att_";

/// Generates a new code like `ABCD-EFGH-JKLM`.
fn generate_code() -> String {
    let mut code = String::with_capacity(CODE_LEN + 2);
    for i in 0..CODE_LEN {
        if i > 0 && i % 4 == 0 {
            code.push('-');
        }
        code.push(ALPHABET[get_rand_between(0, ALPHABET.len() as u64) as usize] as char);
    }
    code
}

/// Normalizes user input: case, separators and confusable characters. `None` if it cannot be a
/// valid code.
pub fn normalize_code(input: &str) -> Option<String> {
    let mut code = String::with_capacity(CODE_LEN);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c if ALPHABET.contains(&(c as u8)) && c.is_ascii() => c,
            _ => return None,
        };
        code.push(c);
    }
    (code.len() == CODE_LEN).then_some(code)
}

/// The encryption key is not used directly, but a key derived from it for this purpose only.
fn hmac(enc_key: &[u8], normalized_code: &str) -> Vec<u8> {
    let key = hmac_sha256::HMAC::mac(b"rauthy-recovery-codes", enc_key);
    hmac_sha256::HMAC::mac(normalized_code.as_bytes(), key).to_vec()
}

fn hash_email(email: &str) -> String {
    hex::encode(hmac_sha256::Hash::hash(
        email.trim().to_lowercase().as_bytes(),
    ))
}

#[derive(Debug, Serialize)]
pub struct RecoveryCodesInfo {
    pub remaining: i64,
    /// Unix timestamp of the current set of codes, if any
    pub created: Option<i64>,
}

pub struct RecoveryCodes;

impl RecoveryCodes {
    /// Replaces all codes of the user with `CODES_COUNT` new ones and returns them in plain text.
    /// They are never stored or shown again.
    pub async fn generate(user_id: &str) -> Result<Vec<String>, ErrorResponse> {
        let enc_keys = EncKeys::get_static();
        let key_id = enc_keys.enc_key_active.clone();
        let key = enc_keys.get_key(&key_id)?;
        let now = Utc::now().timestamp();

        let codes = (0..CODES_COUNT)
            .map(|_| generate_code())
            .collect::<Vec<_>>();
        let hmacs = codes
            .iter()
            .map(|c| hmac(key, &normalize_code(c).unwrap()))
            .collect::<Vec<_>>();

        let sql_delete = "DELETE FROM recovery_codes WHERE user_id = $1";
        let sql_insert = r#"
INSERT INTO recovery_codes (user_id, hmac, key_id, created, used)
VALUES ($1, $2, $3, $4, NULL)"#;

        if is_hiqlite() {
            let mut txn = Vec::with_capacity(CODES_COUNT + 1);
            txn.push((sql_delete, params!(user_id.to_string())));
            for h in hmacs {
                txn.push((
                    sql_insert,
                    params!(user_id.to_string(), h, key_id.clone(), now),
                ));
            }
            DB::hql().txn(txn).await?;
        } else {
            let mut cl = DB::pg().await?;
            let txn = cl.transaction().await?;
            DB::pg_txn_append(&txn, sql_delete, &[&user_id]).await?;
            for h in &hmacs {
                DB::pg_txn_append(&txn, sql_insert, &[&user_id, h, &key_id, &now]).await?;
            }
            txn.commit().await?;
        }

        Ok(codes)
    }

    pub async fn delete_for_user(user_id: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM recovery_codes WHERE user_id = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(user_id.to_string())).await?;
        } else {
            DB::pg_execute(sql, &[&user_id]).await?;
        }
        Ok(())
    }

    pub async fn info(user_id: &str) -> Result<RecoveryCodesInfo, ErrorResponse> {
        let sql = "SELECT COUNT(*) AS remaining, MIN(created) AS created FROM recovery_codes \
            WHERE user_id = $1 AND used IS NULL";
        let (remaining, created): (i64, Option<i64>) = if is_hiqlite() {
            let mut row = DB::hql()
                .query_raw_one(sql, params!(user_id.to_string()))
                .await?;
            (row.get("remaining"), row.get("created"))
        } else {
            let row = DB::pg_query_one_row(sql, &[&user_id]).await?;
            (row.get("remaining"), row.get("created"))
        };
        Ok(RecoveryCodesInfo {
            remaining,
            created: if remaining > 0 { created } else { None },
        })
    }

    /// Marks a matching, unused code as used. Atomic: two requests with the same code can never
    /// both succeed.
    async fn consume(user_id: &str, normalized_code: &str) -> Result<bool, ErrorResponse> {
        let sql_keys =
            "SELECT DISTINCT key_id FROM recovery_codes WHERE user_id = $1 AND used IS NULL";
        let key_ids: Vec<String> = if is_hiqlite() {
            DB::hql()
                .query_raw(sql_keys, params!(user_id.to_string()))
                .await?
                .into_iter()
                .map(|mut row| row.get("key_id"))
                .collect()
        } else {
            DB::pg_query_rows(sql_keys, &[&user_id], 1)
                .await?
                .into_iter()
                .map(|row| row.get("key_id"))
                .collect()
        };

        let now = Utc::now().timestamp();
        let sql = "UPDATE recovery_codes SET used = $1 \
            WHERE user_id = $2 AND hmac = $3 AND key_id = $4 AND used IS NULL";
        for key_id in key_ids {
            let Ok(key) = EncKeys::get_static().get_key(&key_id) else {
                continue;
            };
            let h = hmac(key, normalized_code);
            let rows = if is_hiqlite() {
                DB::hql()
                    .execute(sql, params!(now, user_id.to_string(), h, key_id))
                    .await?
            } else {
                DB::pg_execute(sql, &[&now, &user_id, &h, &key_id]).await?
            };
            if rows == 1 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Counts a generation for the rate limit. `Err` if the user generated too many codes
    /// within 24 h.
    pub async fn check_generate_limit(user_id: &str) -> Result<(), ErrorResponse> {
        let idx = format!("{IDX_GENERATED}{user_id}");
        let now = Utc::now().timestamp();
        let mut stamps: Vec<i64> = DB::hql()
            .get(Cache::Webauthn, &idx)
            .await?
            .unwrap_or_default();
        stamps.retain(|ts| *ts > now - LOCK_WINDOW_SECS);
        if stamps.len() >= GENERATE_MAX_PER_DAY {
            return Err(ErrorResponse::new(
                ErrorResponseType::TooManyRequests(now + LOCK_WINDOW_SECS),
                "Too many new recovery codes within 24 hours",
            ));
        }
        stamps.push(now);
        DB::hql()
            .put(Cache::Webauthn, idx, &stamps, Some(LOCK_WINDOW_SECS))
            .await?;
        Ok(())
    }
}

/// Failed redeem attempts.
///
/// - Per IP (IPv6 per /64): `LOCK_MAX_FAILURES_IP` within 24 h block redeeming from there. The
///   window slides and the block lifts on its own.
/// - Per account, keyed by a hash of the E-Mail so that unknown and existing accounts behave the
///   same: `WARN_FAILURES_ACCOUNT` failures within 24 h send one warning E-Mail. They never block
///   the account, otherwise anyone who knows an E-Mail could keep its recovery locked forever,
///   and with 60-bit codes such a lock would add nothing against guessing.
///
/// Lives in the cache only: a restart resets it.
pub struct RecoveryLock;

/// IPv4 addresses as they are, IPv6 addresses by their /64 network.
fn ip_key(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        _ => ip.to_string(),
    }
}

impl RecoveryLock {
    async fn failures(idx: &str) -> Result<Vec<i64>, ErrorResponse> {
        let now = Utc::now().timestamp();
        let mut stamps: Vec<i64> = DB::hql()
            .get(Cache::Webauthn, idx)
            .await?
            .unwrap_or_default();
        stamps.retain(|ts| *ts > now - LOCK_WINDOW_SECS);
        Ok(stamps)
    }

    async fn add_failure(idx: String) -> Result<usize, ErrorResponse> {
        let mut stamps = Self::failures(&idx).await?;
        stamps.push(Utc::now().timestamp());
        let count = stamps.len();
        DB::hql()
            .put(Cache::Webauthn, idx, &stamps, Some(LOCK_WINDOW_SECS))
            .await?;
        Ok(count)
    }

    /// `true` if redeeming from this IP is blocked.
    pub async fn is_ip_blocked(ip: &str) -> Result<bool, ErrorResponse> {
        let stamps = Self::failures(&format!("{IDX_LOCK_IP}{}", ip_key(ip))).await?;
        Ok(stamps.len() >= LOCK_MAX_FAILURES_IP)
    }

    /// Returns `true` exactly when this failure reached `WARN_FAILURES_ACCOUNT` for the account.
    pub async fn add(email: &str, ip: &str) -> Result<bool, ErrorResponse> {
        Self::add_failure(format!("{IDX_LOCK_IP}{}", ip_key(ip))).await?;
        let count = Self::add_failure(format!("{IDX_LOCK}{}", hash_email(email))).await?;
        Ok(count == WARN_FAILURES_ACCOUNT)
    }

    /// After a successful recovery or a reset by an admin.
    pub async fn clear(email: &str) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::Webauthn, format!("{IDX_LOCK}{}", hash_email(email)))
            .await?;
        Ok(())
    }
}

/// The second step of redeeming: a code sent by E-Mail, entered in the browser that holds the
/// `id`. A challenge exists for every request, also for unknown accounts and invalid codes
/// (`user_id: None`), so that the response is always the same.
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryChallenge {
    pub id: String,
    pub user_id: Option<String>,
    /// SHA-256 of `id` + mail code
    mail_code_hash: Vec<u8>,
    pub exp: i64,
}

impl Debug for RecoveryChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecoveryChallenge {{ id: {}(...), user_id: {:?}, exp: {} }}",
            &self.id[..5],
            self.user_id,
            self.exp
        )
    }
}

/// The result of `RecoveryChallenge::start()`
pub struct RecoveryStart {
    pub challenge: RecoveryChallenge,
    /// The user and the mail code to send, only if the recovery code was valid
    pub mail: Option<(User, String)>,
    /// Set when this failure reached the warning threshold for an existing account
    pub warn_user: Option<User>,
}

impl RecoveryChallenge {
    fn hash_mail_code(id: &str, mail_code: &str) -> Vec<u8> {
        hmac_sha256::Hash::hash(format!("{id}{mail_code}").as_bytes()).to_vec()
    }

    fn new(user_id: Option<String>) -> (Self, String) {
        let mail_code = (0..MAIL_CODE_DIGITS)
            .map(|_| char::from(b'0' + get_rand_between(0, 10) as u8))
            .collect::<String>();
        let id = get_rand(48);
        let slf = Self {
            mail_code_hash: Self::hash_mail_code(&id, &mail_code),
            id,
            user_id,
            exp: Utc::now().timestamp() + MAIL_CODE_LIFETIME_SECS,
        };
        (slf, mail_code)
    }

    async fn save(&self) -> Result<(), ErrorResponse> {
        let client = DB::hql();
        client
            .put(
                Cache::Webauthn,
                format!("{IDX_CHALLENGE}{}", self.id),
                self,
                Some(MAIL_CODE_LIFETIME_SECS),
            )
            .await?;
        // only the newest challenge of a user is valid, see `cancel_for_user()`
        if let Some(user_id) = &self.user_id {
            client
                .put(
                    Cache::Webauthn,
                    format!("{IDX_CHALLENGE_USER}{user_id}"),
                    &self.id,
                    Some(MAIL_CODE_LIFETIME_SECS),
                )
                .await?;
        }
        Ok(())
    }

    async fn delete(id: &str) -> Result<(), ErrorResponse> {
        let client = DB::hql();
        client
            .delete(Cache::Webauthn, format!("{IDX_CHALLENGE}{id}"))
            .await?;
        client
            .counter_del(Cache::Webauthn, format!("{IDX_CHALLENGE_ATTEMPTS}{id}"))
            .await?;
        Ok(())
    }

    /// Ends a recovery in progress, e.g. after new codes or a reset by an admin.
    pub async fn cancel_for_user(user_id: &str) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::Webauthn, format!("{IDX_CHALLENGE_USER}{user_id}"))
            .await?;
        Ok(())
    }

    /// Checks E-Mail + recovery code. Always returns a challenge. The caller sends the mail and
    /// must make the response time independent of the outcome.
    pub async fn start(email: &str, code: &str, ip: &str) -> Result<RecoveryStart, ErrorResponse> {
        let normalized = normalize_code(code);
        let ip_blocked = RecoveryLock::is_ip_blocked(ip).await?;
        let user = User::find_by_email(email.to_string()).await.ok();

        // A code can only be redeemed for an enabled passkey account with a verified E-Mail.
        let candidate = user.filter(Self::is_eligible);

        let mut valid_user = None;
        if !ip_blocked
            && let (Some(user), Some(code)) = (&candidate, &normalized)
            && RecoveryCodes::consume(&user.id, code).await?
        {
            valid_user = candidate.clone();
        }

        let mut warn_user = None;
        if let Some(user) = &valid_user {
            RecoveryLock::clear(&user.email).await?;
        } else if !ip_blocked && RecoveryLock::add(email, ip).await? {
            warn_user = candidate;
        }

        let (challenge, mail_code) = Self::new(valid_user.as_ref().map(|u| u.id.clone()));
        challenge.save().await?;

        Ok(RecoveryStart {
            challenge,
            mail: valid_user.map(|u| (u, mail_code)),
            warn_user,
        })
    }

    fn is_eligible(user: &User) -> bool {
        let now = Utc::now().timestamp();
        user.enabled
            && user.email_verified
            && user.has_webauthn_enabled()
            && user.user_expires.map(|ts| ts > now).unwrap_or(true)
    }

    /// Checks the mail code. On success, the challenge is removed and the user ID returned.
    pub async fn verify(id: &str, mail_code: &str) -> Result<String, ErrorResponse> {
        let err = || {
            ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "The code is invalid or has expired",
            )
        };
        let client = DB::hql();

        // Counted atomically before the comparison, so that parallel requests cannot get more
        // guesses.
        let attempt = client
            .counter_add(Cache::Webauthn, format!("{IDX_CHALLENGE_ATTEMPTS}{id}"), 1)
            .await?;
        if attempt > MAIL_CODE_MAX_ATTEMPTS {
            Self::delete(id).await?;
            return Err(err());
        }

        let Some(slf) = client
            .get::<_, _, Self>(Cache::Webauthn, format!("{IDX_CHALLENGE}{id}"))
            .await?
        else {
            client
                .counter_del(Cache::Webauthn, format!("{IDX_CHALLENGE_ATTEMPTS}{id}"))
                .await?;
            return Err(err());
        };
        if slf.exp < Utc::now().timestamp() {
            Self::delete(id).await?;
            return Err(err());
        }

        let given = Self::hash_mail_code(&slf.id, mail_code.trim());
        let matches = constant_time_eq::constant_time_eq(&given, &slf.mail_code_hash);
        let Some(user_id) = slf.user_id.filter(|_| matches) else {
            if attempt >= MAIL_CODE_MAX_ATTEMPTS {
                Self::delete(id).await?;
            }
            return Err(err());
        };
        Self::delete(id).await?;

        // new codes or a reset by an admin cancel a recovery in progress
        let current: Option<String> = client
            .get(Cache::Webauthn, format!("{IDX_CHALLENGE_USER}{user_id}"))
            .await?;
        if current.as_deref() != Some(id) {
            return Err(err());
        }
        Self::cancel_for_user(&user_id).await?;
        // the account may have changed within the last minutes
        let user = User::find(user_id.clone()).await?;
        if !Self::is_eligible(&user) {
            return Err(err());
        }

        Ok(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_format() {
        for _ in 0..100 {
            let code = generate_code();
            assert_eq!(code.len(), 14, "{code}");
            let parts = code.split('-').collect::<Vec<_>>();
            assert_eq!(parts.len(), 3, "{code}");
            assert!(parts.iter().all(|p| p.len() == 4), "{code}");
            assert!(
                code.chars()
                    .filter(|c| *c != '-')
                    .all(|c| ALPHABET.contains(&(c as u8))),
                "{code}"
            );
            assert_eq!(normalize_code(&code).unwrap().len(), CODE_LEN);
        }
        // 60 bits of randomness
        assert_eq!(ALPHABET.len(), 32);
        assert_ne!(generate_code(), generate_code());
    }

    #[test]
    fn test_normalize_code() {
        assert_eq!(
            normalize_code("abcd-efgh-jkmn").as_deref(),
            Some("ABCDEFGHJKMN")
        );
        assert_eq!(
            normalize_code(" ABCD EFGH JKMN ").as_deref(),
            Some("ABCDEFGHJKMN")
        );
        // confusable characters
        assert_eq!(
            normalize_code("O0Il-0000-0000").as_deref(),
            Some("001100000000")
        );
        assert_eq!(normalize_code("ABCD-EFGH-JKM"), None);
        assert_eq!(normalize_code("ABCD-EFGH-JKMNP"), None);
        assert_eq!(normalize_code("ABCD-EFGH-JKMU"), None);
        assert_eq!(normalize_code("ABCD-EFGH-JKMÄ"), None);
    }

    #[test]
    fn test_hmac_depends_on_key() {
        let a = hmac(b"key-a", "ABCDEFGHJKMN");
        assert_eq!(a.len(), 32);
        assert_eq!(a, hmac(b"key-a", "ABCDEFGHJKMN"));
        assert_ne!(a, hmac(b"key-b", "ABCDEFGHJKMN"));
        assert_ne!(a, hmac(b"key-a", "ABCDEFGHJKMP"));
    }

    #[test]
    fn test_ip_key() {
        assert_eq!(ip_key("192.0.2.7"), "192.0.2.7");
        assert_eq!(
            ip_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            ip_key("2001:db8:1:2::1")
        );
        assert_eq!(ip_key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_ne!(ip_key("2001:db8:1:3::1"), ip_key("2001:db8:1:2::1"));
    }

    #[test]
    fn test_hash_email_normalizes() {
        assert_eq!(hash_email("Anna@Praxis.de "), hash_email("anna@praxis.de"));
        assert_ne!(hash_email("anna@praxis.de"), hash_email("ben@praxis.de"));
    }

    #[test]
    fn test_mail_code_hash() {
        let (c, code) = RecoveryChallenge::new(Some("user".into()));
        assert_eq!(code.len(), MAIL_CODE_DIGITS);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            RecoveryChallenge::hash_mail_code(&c.id, &code),
            c.mail_code_hash
        );
        assert!(!format!("{c:?}").contains(&code));
    }
}
