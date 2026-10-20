use crate::api_cookie::ApiCookie;
use crate::database::DB;
use crate::rauthy_config::RauthyConfig;
use actix_web::HttpRequest;
use chrono::Utc;
use hiqlite::macros::params;
use rauthy_common::constants::{PWD_CSRF_HEADER, PWD_RESET_COOKIE};
use rauthy_common::is_hiqlite;
use rauthy_common::utils::{get_rand, real_ip_from_req};
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::warn;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MagicLinkUsage {
    EmailChange(String),
    PasswordReset(Option<String>),
    NewUser(Option<String>),
    /// Created after a redeemed recovery code, only allows to register a new passkey. It is never
    /// sent by E-Mail and always bound to the browser that redeemed the code.
    PasskeyRecovery,
}

impl TryFrom<&String> for MagicLinkUsage {
    type Error = ErrorResponse;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for MagicLinkUsage {
    type Error = ErrorResponse;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (ty, v) = value.split_once('$').unwrap_or((value, ""));
        let slf = match ty {
            "email_change" => MagicLinkUsage::EmailChange(v.to_string()),
            "passkey_recovery" => MagicLinkUsage::PasskeyRecovery,
            "new_user" => {
                if !v.is_empty() {
                    MagicLinkUsage::NewUser(Some(v.to_string()))
                } else {
                    MagicLinkUsage::NewUser(None)
                }
            }
            "password_reset" => {
                if !v.is_empty() {
                    MagicLinkUsage::PasswordReset(Some(v.to_string()))
                } else {
                    MagicLinkUsage::PasswordReset(None)
                }
            }
            _ => {
                return Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "Invalid string for MagicLinkUsage parsing",
                ));
            }
        };

        Ok(slf)
    }
}

impl MagicLinkUsage {
    /// `true` if a link with this usage may only be used to register a passkey, never to set a
    /// password, see `webauthn.new_user_passkey_only`.
    pub fn is_passkey_only(&self, new_user_passkey_only: bool) -> bool {
        match self {
            Self::NewUser(_) => new_user_passkey_only,
            Self::PasskeyRecovery => true,
            Self::EmailChange(_) | Self::PasswordReset(_) => false,
        }
    }
}

impl Display for MagicLinkUsage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // For types with a value, `$` was chosen as the separating characters since it is URL safe.
        // It also makes splitting of the value quite easy.
        match self {
            MagicLinkUsage::EmailChange(email) => write!(f, "email_change${email}"),
            MagicLinkUsage::PasskeyRecovery => write!(f, "passkey_recovery"),
            MagicLinkUsage::NewUser(redirect_uri) => {
                if let Some(uri) = redirect_uri {
                    write!(f, "new_user${uri}")
                } else {
                    write!(f, "new_user")
                }
            }
            MagicLinkUsage::PasswordReset(redirect_uri) => {
                if let Some(uri) = redirect_uri {
                    write!(f, "password_reset${uri}")
                } else {
                    write!(f, "password_reset")
                }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, FromPgRow)]
pub struct MagicLink {
    pub id: String,
    pub user_id: String,
    pub csrf_token: String,
    pub cookie: Option<String>,
    pub exp: i64,
    pub used: bool,
    pub usage: String,
}

impl Debug for MagicLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MagicLink {{ id: {}(...), user_id: {}, csrf_token: {}(...), cookie: {:?}, exp: {}, \
            used: {}, usage: {} }}",
            &self.id[..5],
            self.user_id,
            &self.csrf_token[..5],
            self.cookie,
            self.exp,
            self.used,
            self.usage
        )
    }
}

// CRUD
impl MagicLink {
    pub async fn create(
        user_id: String,
        lifetime: Duration,
        usage: MagicLinkUsage,
    ) -> Result<Self, ErrorResponse> {
        let id = get_rand(64);
        let exp = OffsetDateTime::now_utc().add(lifetime).unix_timestamp();
        let link = MagicLink {
            id,
            user_id,
            csrf_token: get_rand(48),
            cookie: None,
            exp,
            used: false,
            usage: usage.to_string(),
        };

        let sql = r#"
INSERT INTO magic_links (id, user_id, csrf_token, exp, used, usage)
VALUES ($1, $2, $3, $4, $5, $6)"#;

        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(
                        link.id.clone(),
                        link.user_id.clone(),
                        link.csrf_token.clone(),
                        link.exp,
                        false,
                        link.usage.clone()
                    ),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[
                    &link.id,
                    &link.user_id,
                    &link.csrf_token,
                    &link.exp,
                    &false,
                    &link.usage,
                ],
            )
            .await?;
        }

        Ok(link)
    }

    /// Deletes all links of a user that can be used to set up credentials (`password_reset`,
    /// `new_user` and `passkey_recovery`), so that only a freshly sent one stays valid.
    pub async fn delete_all_credential_links_for_user(user_id: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM magic_links WHERE user_id = $1 \
            AND (usage LIKE 'password_reset%' OR usage LIKE 'new_user%' \
            OR usage LIKE 'passkey_recovery%')";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(user_id)).await?;
        } else {
            DB::pg_execute(sql, &[&user_id]).await?;
        };

        Ok(())
    }

    pub async fn delete_all_pwd_reset_for_user(user_id: String) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM magic_links WHERE user_id = $1 AND usage LIKE 'password_reset%'";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(user_id)).await?;
        } else {
            DB::pg_execute(sql, &[&user_id]).await?;
        };

        Ok(())
    }

    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        let sql = "SELECT * FROM magic_links WHERE id = $1";
        let res = if is_hiqlite() {
            DB::hql().query_as_one(sql, params!(id)).await?
        } else {
            DB::pg_query_one(sql, &[&id]).await?
        };

        Ok(res)
    }

    pub async fn find_by_user(user_id: String) -> Result<MagicLink, ErrorResponse> {
        let sql = "SELECT * FROM magic_links WHERE user_id = $1";
        let res = if is_hiqlite() {
            DB::hql().query_as_one(sql, params!(user_id)).await?
        } else {
            DB::pg_query_one(sql, &[&user_id]).await?
        };

        Ok(res)
    }

    pub async fn invalidate_all_email_change(user_id: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM magic_links WHERE user_id = $1 AND usage LIKE 'email_change$%'";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(user_id)).await?;
        } else {
            DB::pg_execute(sql, &[&user_id]).await?;
        };

        Ok(())
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        let sql = "UPDATE magic_links SET cookie = $1, exp = $2, used = $3 WHERE id = $4";
        if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(&self.cookie, self.exp, self.used, &self.id))
                .await?;
        } else {
            DB::pg_execute(sql, &[&self.cookie, &self.exp, &self.used, &self.id]).await?;
        }

        Ok(())
    }
}

impl MagicLink {
    /// Sets the magic link as being expired and used.
    pub async fn invalidate(&mut self) -> Result<(), ErrorResponse> {
        self.exp = Utc::now().timestamp() - 10;
        self.used = true;
        self.save().await
    }

    pub fn validate(
        &self,
        user_id: &str,
        req: &HttpRequest,
        with_csrf: bool,
    ) -> Result<(), ErrorResponse> {
        // binding cookie
        let is_recovery = self.usage == MagicLinkUsage::PasskeyRecovery.to_string();
        if is_recovery && self.cookie.is_none() {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "A recovery link must be bound to the browser that redeemed the code",
            ));
        }

        if let Some(cookie_slf) = &self.cookie {
            let err = ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "The requested password reset link is already tied to another session",
            );

            // A recovery link is never sent by E-Mail, so the binding is always enforced.
            let cookie_binding = RauthyConfig::get()
                .vars
                .access
                .password_reset_cookie_binding
                || is_recovery;
            if let Some(cookie) = ApiCookie::from_req(req, PWD_RESET_COOKIE) {
                // the extracted cookie from the request starts with 'rauthy-pwd-reset='
                let binding_matches = cookie.len() >= cookie_slf.len()
                    && constant_time_eq::constant_time_eq(
                        &cookie.as_bytes()[cookie.len() - cookie_slf.len()..],
                        cookie_slf.as_bytes(),
                    );
                if !binding_matches {
                    if cookie_binding {
                        return Err(err);
                    } else {
                        let ip = real_ip_from_req(req)?;
                        warn!(
                            ?ip,
                            "PASSWORD_RESET_COOKIE_BINDING disabled -> ignoring invalid binding \
                            cookie",
                        );
                    }
                }
            } else if cookie_binding {
                return Err(err);
            } else {
                let ip = real_ip_from_req(req)?;
                warn!(
                    ?ip,
                    "PASSWORD_RESET_COOKIE_BINDING disabled -> ignoring invalid binding cookie",
                );
            }
        }

        // csrf token
        if with_csrf {
            match req.headers().get(PWD_CSRF_HEADER) {
                None => {
                    return Err(ErrorResponse::new(
                        ErrorResponseType::Unauthorized,
                        "CSRF Token is missing",
                    ));
                }
                Some(token) => {
                    if !constant_time_eq::constant_time_eq(
                        self.csrf_token.as_bytes(),
                        token.to_str().unwrap_or("").as_bytes(),
                    ) {
                        return Err(ErrorResponse::new(
                            ErrorResponseType::Unauthorized,
                            "Invalid CSRF Token",
                        ));
                    }
                }
            }
        }

        if self.user_id != user_id {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Invalid User ID",
            ));
        }

        if self.exp < OffsetDateTime::now_utc().unix_timestamp() {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "This link has expired already",
            ));
        }

        if self.used {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "The requested link has been used already",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdxMagicLinkPasswordUser {
    pub user_id: String,
    pub id: String,
}

impl IdxMagicLinkPasswordUser {
    pub fn from_magic_link(ml: &MagicLink) -> Self {
        Self {
            user_id: ml.user_id.clone(),
            id: ml.id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entity::magic_links::MagicLinkUsage;

    #[test]
    fn test_magic_link_usage_conversions() {
        let ml = MagicLinkUsage::NewUser(None);
        let s = ml.to_string();
        let ml_from = MagicLinkUsage::try_from(&s).unwrap();
        assert_eq!(ml, ml_from);

        let ml = MagicLinkUsage::NewUser(Some("custom.uri.com".to_string()));
        let s = ml.to_string();
        let ml_from = MagicLinkUsage::try_from(&s).unwrap();
        assert_eq!(ml, ml_from);

        let ml = MagicLinkUsage::PasswordReset(None);
        let s = ml.to_string();
        let ml_from = MagicLinkUsage::try_from(&s).unwrap();
        assert_eq!(ml, ml_from);

        let ml = MagicLinkUsage::PasswordReset(Some("custom.uri.com".to_string()));
        let s = ml.to_string();
        let ml_from = MagicLinkUsage::try_from(&s).unwrap();
        assert_eq!(ml, ml_from);

        let ml = MagicLinkUsage::EmailChange("admin@localhost".to_string());
        let s = ml.to_string();
        let ml_from = MagicLinkUsage::try_from(&s).unwrap();
        assert_eq!(ml, ml_from);
    }

    #[test]
    fn test_magic_link_usage_passkey_only() {
        // the upstream default never restricts anything
        for usage in [
            MagicLinkUsage::NewUser(None),
            MagicLinkUsage::NewUser(Some("custom.uri.com".to_string())),
            MagicLinkUsage::PasswordReset(None),
            MagicLinkUsage::EmailChange("admin@localhost".to_string()),
        ] {
            assert!(!usage.is_passkey_only(false), "{usage}");
        }

        // only the setup of a new account is restricted to a passkey
        assert!(MagicLinkUsage::NewUser(None).is_passkey_only(true));
        assert!(MagicLinkUsage::NewUser(Some("custom.uri.com".to_string())).is_passkey_only(true));
        assert!(!MagicLinkUsage::PasswordReset(None).is_passkey_only(true));
        assert!(!MagicLinkUsage::EmailChange("admin@localhost".to_string()).is_passkey_only(true));

        // a recovery link only ever registers a passkey, no matter the config
        assert!(MagicLinkUsage::PasskeyRecovery.is_passkey_only(false));
        assert!(MagicLinkUsage::PasskeyRecovery.is_passkey_only(true));
    }

    #[test]
    fn test_magic_link_usage_passkey_recovery_roundtrip() {
        let s = MagicLinkUsage::PasskeyRecovery.to_string();
        assert_eq!(s, "passkey_recovery");
        assert_eq!(
            MagicLinkUsage::try_from(s.as_str()).unwrap(),
            MagicLinkUsage::PasskeyRecovery
        );
    }
}
