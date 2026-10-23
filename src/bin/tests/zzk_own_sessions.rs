use crate::common::{get_auth_headers, get_backend_url, session_headers, session_headers_with};
use pretty_assertions::assert_eq;
use rauthy_api_types::generic::Language;
use rauthy_api_types::users::{NewUserRequest, UpdateUserRequest, UserResponse};
use rauthy_common::constants::CSRF_HEADER;
use reqwest::Client;
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use std::error::Error;

mod common;

const EMAIL: &str = "own-sessions@ostest.io";
// Also valid under the strict policy that `zzb_handler_password_policy` leaves behind
const PWD: &str = "Own!Sess#2Ion$3Te%4St&5";

/// A dedicated user, so that ending "all other sessions" never touches other tests.
async fn create_user(client: &Client, backend: &str, admin: &HeaderMap) -> UserResponse {
    // a left-over from an aborted run
    let res = client
        .get(format!("{backend}/users/email/{EMAIL}"))
        .headers(admin.clone())
        .send()
        .await
        .unwrap();
    if res.status() == 200 {
        let old = res.json::<UserResponse>().await.unwrap();
        client
            .delete(format!("{backend}/users/{}", old.id))
            .headers(admin.clone())
            .send()
            .await
            .unwrap();
    }

    let payload = NewUserRequest {
        given_name: Some("Own".to_string()),
        family_name: Some("Sessions".to_string()),
        email: EMAIL.to_string(),
        preferred_username: None,
        language: Language::En,
        roles: Vec::new(),
        groups: None,
        user_expires: None,
        tz: None,
        send_setup_mail: None,
    };
    let res = client
        .post(format!("{backend}/users"))
        .headers(admin.clone())
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let user = res.json::<UserResponse>().await.unwrap();

    let upd = UpdateUserRequest {
        email: user.email.clone(),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        language: Some(Language::En),
        password: Some(PWD.to_string()),
        roles: user.roles.clone(),
        groups: user.groups.clone(),
        enabled: true,
        email_verified: true,
        user_expires: None,
        user_values: None,
    };
    let res = client
        .put(format!("{backend}/users/{}", user.id))
        .headers(admin.clone())
        .json(&upd)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    user
}

async fn list(client: &Client, backend: &str, uid: &str, headers: &HeaderMap) -> (u16, Value) {
    let res = client
        .get(format!("{backend}/users/{uid}/sessions"))
        .headers(headers.clone())
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json::<Value>().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn test_own_sessions() -> Result<(), Box<dyn Error>> {
    let backend = get_backend_url();
    let client = Client::new();
    let admin = get_auth_headers().await?;
    let user = create_user(&client, &backend, &admin).await;
    let uid = user.id.as_str();

    // two logins of the same person, e.g. two computers
    let first = session_headers_with(EMAIL, PWD).await;
    let second = session_headers_with(EMAIL, PWD).await;

    // the list shows both, marks the current one, and has no IDs or IP addresses
    let (status, body) = list(&client, &backend, uid, &first).await;
    assert_eq!(status, 200, "{body}");
    let sessions = body.as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions.iter().filter(|s| s["current"] == true).count(),
        1,
        "{body}"
    );
    for s in sessions {
        assert!(s.get("id").is_none(), "{s}");
        assert!(s.get("remote_ip").is_none(), "{s}");
    }

    // another person must neither see nor end these sessions
    let (other, _) = session_headers().await;
    let (status, _) = list(&client, &backend, uid, &other).await;
    assert_eq!(status, 403);
    // without a session
    let res = client
        .get(format!("{backend}/users/{uid}/sessions"))
        .send()
        .await?;
    assert_eq!(res.status(), 401);

    // a fresh MfaModToken of this very user, for a password-only account via the password
    let res = client
        .post(format!("{backend}/users/{uid}/mfa_token"))
        .headers(first.clone())
        .json(&json!({ "password": PWD }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let token = res.json::<Value>().await?["id"]
        .as_str()
        .unwrap()
        .to_string();

    let url_delete = format!("{backend}/users/{uid}/sessions");
    // another person, even with this token
    let res = client
        .delete(&url_delete)
        .headers(other.clone())
        .json(&json!({ "mfa_mod_token_id": token }))
        .send()
        .await?;
    assert_eq!(res.status(), 403);

    // without the CSRF token
    let mut no_csrf = first.clone();
    no_csrf.remove(CSRF_HEADER);
    let res = client
        .delete(&url_delete)
        .headers(no_csrf)
        .json(&json!({ "mfa_mod_token_id": token }))
        .send()
        .await?;
    assert_eq!(res.status(), 401);

    // without a token, or with an unknown one
    let res = client
        .delete(&url_delete)
        .headers(first.clone())
        .json(&json!({}))
        .send()
        .await?;
    assert_eq!(res.status(), 400);
    let res = client
        .delete(&url_delete)
        .headers(first.clone())
        .json(&json!({ "mfa_mod_token_id": "a".repeat(32) }))
        .send()
        .await?;
    assert_eq!(res.status(), 401);

    // nothing has been ended so far
    let (status, body) = list(&client, &backend, uid, &second).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 2);

    // "log out everywhere else"
    let res = client
        .delete(&url_delete)
        .headers(first.clone())
        .json(&json!({ "mfa_mod_token_id": token }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    let (status, body) = list(&client, &backend, uid, &first).await;
    assert_eq!(status, 200);
    let sessions = body.as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["current"], true);
    let (status, _) = list(&client, &backend, uid, &second).await;
    assert_eq!(status, 401);

    let res = client
        .delete(format!("{backend}/users/{uid}"))
        .headers(admin)
        .send()
        .await?;
    assert_eq!(res.status(), 204);

    Ok(())
}
