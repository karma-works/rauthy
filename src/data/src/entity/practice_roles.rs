//! Optional practice-wide roles. Personal PINs are never converted implicitly.
//! A role is bound to a practice account; device possession plus PIN selects its permissions.
use crate::database::DB;
use crate::entity::sessions::Session;
use crate::entity::shared_devices::{SharedDevice, is_valid_pin_format};
use chrono::Utc;
use cryptr::EncKeys;
use hiqlite::macros::{FromRow, params};
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::Serialize;

pub const ROLES: [&str; 3] = ["administration", "management", "staff"];
pub const LOCK_SECONDS: i64 = 300;

pub fn validate_role(role: &str) -> Result<(), ErrorResponse> {
    if ROLES.contains(&role) {
        Ok(())
    } else {
        Err(denied())
    }
}

fn denied() -> ErrorResponse {
    ErrorResponse::new(ErrorResponseType::Forbidden, "Practice role not available")
}

#[derive(Clone, FromRow, FromPgRow)]
pub struct PracticeRole {
    pub practice_id: String,
    pub role: String,
    pub user_id: String,
    pub pin_hmac: Option<Vec<u8>>,
    pub pin_key_id: Option<String>,
    pub pin_version: i64,
}

fn hash(key: &[u8], practice: &str, role: &str, pin: &str) -> Vec<u8> {
    let key = hmac_sha256::HMAC::mac(b"rauthy-practice-role-pin-v1", key);
    hmac_sha256::HMAC::mac(format!("{practice}\0{role}\0{pin}"), key).to_vec()
}

impl PracticeRole {
    pub async fn find(practice: &str, role: &str) -> Result<Option<Self>, ErrorResponse> {
        validate_role(role)?;
        let sql = "SELECT * FROM shared_practice_roles WHERE practice_id = $1 AND role = $2";
        if is_hiqlite() {
            Ok(DB::hql()
                .query_map_optional(sql, params!(practice.to_string(), role.to_string()))
                .await?)
        } else {
            DB::pg_query_opt(sql, &[&practice, &role]).await
        }
    }

    /// Repeating enable does not reassign the account or overwrite PINs.
    pub async fn enable(practice: &str, user: &str) -> Result<(), ErrorResponse> {
        // Insert all roles in one statement so concurrent setup cannot split their owner.
        let sql = "INSERT INTO shared_practice_roles (practice_id, role, user_id) VALUES \
            ($1, 'administration', $2), ($1, 'management', $2), ($1, 'staff', $2) \
            ON CONFLICT(practice_id, role) DO NOTHING";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(practice.to_string(), user.to_string()))
                .await?;
        } else {
            DB::pg_execute(sql, &[&practice, &user]).await?;
        }
        for role in ROLES {
            if Self::find(practice, role)
                .await?
                .is_none_or(|existing| existing.user_id != user)
            {
                return Err(denied());
            }
        }
        let sql = "UPDATE shared_device_practices SET role_mode = true WHERE id = $1";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(practice.to_string()))
                .await?;
        } else {
            DB::pg_execute(sql, &[&practice]).await?;
        }
        Ok(())
    }

    pub async fn set_pin(&self, pin: &str) -> Result<(), ErrorResponse> {
        if !is_valid_pin_format(pin) {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "PIN must have four digits",
            ));
        }
        let keys = EncKeys::get_static();
        let key_id = keys.enc_key_active.clone();
        let digest = hash(keys.get_key(&key_id)?, &self.practice_id, &self.role, pin);
        let sql = "UPDATE shared_practice_roles SET pin_hmac = $1, pin_key_id = $2, pin_version = pin_version + 1 \
                   WHERE practice_id = $3 AND role = $4 AND user_id = $5";
        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(
                        digest,
                        key_id,
                        self.practice_id.clone(),
                        self.role.clone(),
                        self.user_id.clone()
                    ),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[
                    &digest,
                    &key_id,
                    &self.practice_id,
                    &self.role,
                    &self.user_id,
                ],
            )
            .await?;
        }
        // End all sessions using the old PIN, including their refresh tokens. A reset does not unlock attempts.
        let sql = "SELECT session_id AS id FROM shared_role_sessions WHERE practice_id = $1 AND role = $2";
        let sessions: Vec<Id> = if is_hiqlite() {
            DB::hql()
                .query_map(sql, params!(self.practice_id.clone(), self.role.clone()))
                .await?
        } else {
            DB::pg_query(sql, &[&self.practice_id, &self.role], 16).await?
        };
        for session in sessions {
            if let Ok(found) = Session::find(session.id).await {
                crate::entity::refresh_tokens::RefreshToken::delete_by_sid(found.id.clone())
                    .await?;
                found.delete().await?;
            }
        }
        Ok(())
    }

    pub fn matches(&self, pin: &str) -> Result<bool, ErrorResponse> {
        let (Some(digest), Some(key_id)) = (&self.pin_hmac, &self.pin_key_id) else {
            return Ok(false);
        };
        let computed = hash(
            EncKeys::get_static().get_key(key_id)?,
            &self.practice_id,
            &self.role,
            pin,
        );
        // Fixed-size comparison; no PIN or digest is logged.
        Ok(digest.len() == computed.len()
            && digest
                .iter()
                .zip(&computed)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0)
    }
}

#[derive(FromRow, FromPgRow)]
struct Id {
    id: String,
}

#[derive(FromRow, FromPgRow)]
struct Attempts {
    failures: i64,
    locked_until: i64,
}

/// Reserve before comparing the PIN, atomically. Parallel attempts cannot exceed five.
pub async fn reserve(device: &str, role: &str) -> Result<Option<i64>, ErrorResponse> {
    validate_role(role)?;
    let now = Utc::now().timestamp();
    let sql = "INSERT INTO shared_role_attempts(device_id, role, failures, locked_until) \
        VALUES ($1, $2, 1, 0) ON CONFLICT(device_id, role) DO UPDATE SET \
        failures = CASE WHEN shared_role_attempts.locked_until > 0 THEN 1 ELSE shared_role_attempts.failures + 1 END, \
        locked_until = CASE WHEN shared_role_attempts.locked_until = 0 AND shared_role_attempts.failures = 4 THEN CAST($3 AS BIGINT) + 300 ELSE 0 END WHERE shared_role_attempts.locked_until <= $3 \
        AND (shared_role_attempts.failures < 5 OR shared_role_attempts.locked_until > 0) \
        RETURNING failures, locked_until";
    let result: Option<Attempts> = if is_hiqlite() {
        let mut rows = DB::hql()
            .execute_returning(sql, params!(device.to_string(), role.to_string(), now))
            .await?;
        if rows.is_empty() {
            None
        } else {
            {
                let mut row = rows.remove(0)?;
                Some(Attempts {
                    failures: row.get("failures"),
                    locked_until: row.get("locked_until"),
                })
            }
        }
    } else {
        DB::pg_query_opt(sql, &[&device, &role, &now]).await?
    };
    Ok(result
        .filter(|a| {
            a.failures <= 5 && (a.locked_until == 0 || a.locked_until == now + LOCK_SECONDS)
        })
        .map(|a| a.failures))
}

pub async fn finish_attempt(device: &str, role: &str, success: bool) -> Result<(), ErrorResponse> {
    let now = Utc::now().timestamp();
    let sql = if success {
        "UPDATE shared_role_attempts SET failures = 0, locked_until = 0 WHERE device_id = $1 AND role = $2 "
    } else {
        "UPDATE shared_role_attempts SET locked_until = $3 WHERE device_id = $1 AND role = $2 AND failures >= 5 AND locked_until = 0"
    };
    if is_hiqlite() {
        if success {
            DB::hql()
                .execute(sql, params!(device.to_string(), role.to_string()))
                .await?;
        } else {
            DB::hql()
                .execute(
                    sql,
                    params!(device.to_string(), role.to_string(), now + LOCK_SECONDS),
                )
                .await?;
        }
    } else if success {
        DB::pg_execute(sql, &[&device, &role]).await?;
    } else {
        DB::pg_execute(sql, &[&device, &role, &(now + LOCK_SECONDS)]).await?;
    }
    Ok(())
}

pub async fn bind(
    session: &str,
    practice: &str,
    role: &str,
    pin_version: i64,
) -> Result<(), ErrorResponse> {
    let sql = "INSERT INTO shared_role_sessions(session_id, practice_id, role, pin_version) VALUES ($1, $2, $3, $4)";
    if is_hiqlite() {
        DB::hql()
            .execute(
                sql,
                params!(
                    session.to_string(),
                    practice.to_string(),
                    role.to_string(),
                    pin_version
                ),
            )
            .await?;
    } else {
        DB::pg_execute(sql, &[&session, &practice, &role, &pin_version]).await?;
    }
    Ok(())
}

#[derive(Serialize, FromRow, FromPgRow)]
pub struct RoleSession {
    pub pin_version: i64,
    pub current_version: i64,
    pub practice_id: String,
    pub role: String,
}

pub async fn for_session(session: &str) -> Result<Option<RoleSession>, ErrorResponse> {
    let sql = "SELECT s.practice_id, s.role, s.pin_version, r.pin_version AS current_version \
        FROM shared_role_sessions s JOIN shared_practice_roles r \
        ON s.practice_id = r.practice_id AND s.role = r.role WHERE s.session_id = $1";
    let result: Option<RoleSession> = if is_hiqlite() {
        DB::hql()
            .query_map_optional(sql, params!(session.to_string()))
            .await?
    } else {
        DB::pg_query_opt(sql, &[&session]).await?
    };
    if result
        .as_ref()
        .is_some_and(|r| r.pin_version != r.current_version)
    {
        return Err(denied());
    }
    Ok(result)
}

/// Read on every protected request: no cache of revocation or selected role.
pub async fn live_session(id: &str) -> Result<serde_json::Value, ErrorResponse> {
    let session = Session::find(id.to_string()).await?;
    if session.exp <= Utc::now().timestamp() {
        return Err(denied());
    }
    let device =
        SharedDevice::find(session.shared_device_id.as_deref().ok_or_else(denied)?).await?;
    let role = for_session(id).await?;
    if role.is_some() && !enabled(&device.practice_id).await? {
        return Err(denied());
    }
    if session.user_id.is_none() || session.state != crate::entity::sessions::SessionState::Auth {
        return Err(denied());
    }
    Ok(serde_json::json!({"session_id": id, "device_id": device.id,
        "practice_id": device.practice_id, "user_id": session.user_id,
        "role": role.map(|r| r.role)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_separation_and_role_validation() {
        assert_ne!(
            hash(&[1; 32], "p", "staff", "0123"),
            hash(&[1; 32], "p", "administration", "0123")
        );
        assert_ne!(
            hash(&[1; 32], "p", "staff", "0123"),
            hash(&[1; 32], "other", "staff", "0123")
        );
        assert!(validate_role("staff").is_ok());
        assert!(validate_role("operator").is_err());
    }
}

/// Password-only lock. Passkey and device authentication never read this counter.
pub async fn validate_account_password(
    user: &crate::entity::users::User,
    password: String,
) -> Result<(), ErrorResponse> {
    let now = Utc::now().timestamp();
    let sql = "INSERT INTO practice_password_attempts(user_id, failures, locked_until) VALUES ($1, 1, 0) \
        ON CONFLICT(user_id) DO UPDATE SET \
        failures = CASE WHEN practice_password_attempts.locked_until > 0 THEN 1 ELSE practice_password_attempts.failures + 1 END, \
        locked_until = CASE WHEN practice_password_attempts.locked_until = 0 AND practice_password_attempts.failures = 4 THEN CAST($2 AS BIGINT) + 900 ELSE 0 END \
        WHERE practice_password_attempts.locked_until <= $2 \
        AND (practice_password_attempts.failures < 5 OR practice_password_attempts.locked_until > 0) RETURNING failures, locked_until";
    let allowed = if is_hiqlite() {
        !DB::hql()
            .execute_returning(sql, params!(user.id.clone(), now))
            .await?
            .is_empty()
    } else {
        DB::pg_query_opt::<Attempts>(sql, &[&user.id, &now])
            .await?
            .is_some()
    };
    // Hash even during a lock, retaining the normal login timing and generic failure.
    let result = user.validate_password(password).await;
    if !allowed {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Invalid credentials",
        ));
    }
    result?;
    let sql = "DELETE FROM practice_password_attempts WHERE user_id = $1";
    if is_hiqlite() {
        DB::hql().execute(sql, params!(user.id.clone())).await?;
    } else {
        DB::pg_execute(sql, &[&user.id]).await?;
    }
    Ok(())
}

pub async fn enabled(practice: &str) -> Result<bool, ErrorResponse> {
    let sql = "SELECT id FROM shared_device_practices WHERE id = $1 AND role_mode = true";
    let found: Option<Id> = if is_hiqlite() {
        DB::hql()
            .query_map_optional(sql, params!(practice.to_string()))
            .await?
    } else {
        DB::pg_query_opt(sql, &[&practice]).await?
    };
    Ok(found.is_some())
}

/// Preserve PIN data for a rollback; end all role and device sessions before switching mode.
pub async fn disable(practice: &str) -> Result<(), ErrorResponse> {
    for device in SharedDevice::find_for_practice(practice).await? {
        crate::entity::shared_devices::end_device_sessions(&device.id, None).await?;
    }
    let sql = "UPDATE shared_device_practices SET role_mode = false WHERE id = $1";
    if is_hiqlite() {
        DB::hql()
            .execute(sql, params!(practice.to_string()))
            .await?;
    } else {
        DB::pg_execute(sql, &[&practice]).await?;
    }
    Ok(())
}

pub async fn cleanup_expired_locks() -> Result<(), ErrorResponse> {
    let now = Utc::now().timestamp();
    for sql in [
        "DELETE FROM shared_role_attempts WHERE locked_until > 0 AND locked_until <= $1",
        "DELETE FROM practice_password_attempts WHERE locked_until > 0 AND locked_until <= $1",
    ] {
        if is_hiqlite() {
            DB::hql().execute(sql, params!(now)).await?;
        } else {
            DB::pg_execute(sql, &[&now]).await?;
        }
    }
    Ok(())
}
