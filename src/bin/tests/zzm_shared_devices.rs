use crate::common::{get_auth_headers, get_backend_url};
use rauthy_api_types::shared_devices::{
    PinLoginErrorResponse, SharedDevicePracticeRequest, SharedDevicePracticeResponse,
    SharedDeviceRegistrationRequest,
};
use rauthy_api_types::users::UserResponseSimple;
use reqwest::Client;
use serde_json::json;
use std::error::Error;

mod common;

/// The admin API and the requests a browser without a registered device can make. The flow with
/// a device and passkeys is covered by `frontend/tests/shared-devices.live.mjs`.
#[tokio::test]
async fn test_shared_devices_admin_api() -> Result<(), Box<dyn Error>> {
    let backend = get_backend_url();
    let client = Client::new();
    let admin = get_auth_headers().await?;
    let practice = format!("praxis-{}", chrono::Utc::now().timestamp_millis());
    let url_practice = format!("{backend}/shared_devices/practices/{practice}");

    // no auth
    let res = client.get(&url_practice).send().await?;
    assert_eq!(res.status(), 401);

    // invalid ID and idle timeout
    let req = SharedDevicePracticeRequest {
        name: "Praxis Test".to_string(),
        idle_timeout: Some(60),
        notify_user_ids: Vec::new(),
    };
    let res = client
        .put(format!("{backend}/shared_devices/practices/not%20valid"))
        .headers(admin.clone())
        .json(&json!({"name": "x", "notify_user_ids": []}))
        .send()
        .await?;
    assert_eq!(res.status(), 400);
    let res = client
        .put(&url_practice)
        .headers(admin.clone())
        .json(&req)
        .send()
        .await?;
    assert_eq!(res.status(), 400, "idle timeout below 120 s");

    let users = client
        .get(format!("{backend}/users"))
        .headers(admin.clone())
        .send()
        .await?
        .json::<Vec<UserResponseSimple>>()
        .await?;
    let admin_id = users
        .iter()
        .find(|u| u.email == "init_admin@localhost")
        .unwrap()
        .id
        .clone();

    let req = SharedDevicePracticeRequest {
        name: "Praxis Test".to_string(),
        idle_timeout: None,
        notify_user_ids: vec![admin_id.clone()],
    };
    let res = client
        .put(&url_practice)
        .headers(admin.clone())
        .json(&req)
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let p = res.json::<SharedDevicePracticeResponse>().await?;
    assert_eq!(p.idle_timeout, 300);
    assert_eq!(p.notify_user_ids, vec![admin_id.clone()]);
    assert!(p.devices.is_empty() && p.members.is_empty() && p.risk_ack_at.is_none());

    // members
    let res = client
        .put(format!("{url_practice}/members/doesNotExist123"))
        .headers(admin.clone())
        .send()
        .await?;
    assert_eq!(res.status(), 404);
    for _ in 0..2 {
        let res = client
            .put(format!("{url_practice}/members/{admin_id}"))
            .headers(admin.clone())
            .send()
            .await?;
        assert_eq!(res.status(), 204);
    }
    let p = client
        .get(&url_practice)
        .headers(admin.clone())
        .send()
        .await?
        .json::<SharedDevicePracticeResponse>()
        .await?;
    assert_eq!(p.members.len(), 1);
    assert!(!p.members[0].has_pin);

    // a registration needs a user with a passkey
    let reg = SharedDeviceRegistrationRequest {
        user_id: admin_id.clone(),
        label: "Empfang 1".to_string(),
        return_uri: None,
    };
    let res = client
        .post(format!("{url_practice}/registrations"))
        .headers(admin.clone())
        .json(&reg)
        .send()
        .await?;
    assert_eq!(res.status(), 400);

    let res = client
        .get(format!("{url_practice}/events"))
        .headers(admin.clone())
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    // without a device cookie
    let res = client
        .post(format!("{backend}/shared_devices/challenge"))
        .send()
        .await?;
    assert_eq!(res.status(), 401);
    let res = client
        .delete(format!("{backend}/shared_devices/devices/doesNotExist"))
        .headers(admin.clone())
        .send()
        .await?;
    assert_eq!(res.status(), 404);

    // a PIN login needs at least a login session
    let res = client
        .post(format!("{backend}/oidc/authorize/pin"))
        .json(&json!({
            "pin": "1357",
            "challenge_id": "a".repeat(32),
            "signature": "abc",
            "client_id": "pin-test",
            "redirect_uri": "http://localhost:8081/auth/v1/oidc/callback",
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 401);

    // ... and the device of the browser
    let res = client
        .get(format!(
            "{backend}/oidc/authorize?client_id=rauthy&redirect_uri={backend}/oidc/callback\
            &response_type=code&code_challenge={}&code_challenge_method=S256",
            "a".repeat(43)
        ))
        .send()
        .await?;
    let cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("; ");
    let html = res.text().await?;
    assert!(!html.contains("tpl_shared_device"));
    let (_, rest) = html
        .split_once(r#"<template id="tpl_csrf_token">"#)
        .unwrap();
    let (csrf, _) = rest.split_once("</template>").unwrap();
    let res = client
        .post(format!("{backend}/oidc/authorize/pin"))
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .json(&json!({
            "pin": "1357",
            "challenge_id": "a".repeat(32),
            "signature": "abc",
            "client_id": "pin-test",
            "redirect_uri": "http://localhost:8081/auth/v1/oidc/callback",
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 401);
    let err = res.json::<PinLoginErrorResponse>().await?;
    assert_eq!(err.error, "invalid_device");

    // removing the member and the practice
    let res = client
        .delete(format!("{url_practice}/members/{admin_id}"))
        .headers(admin.clone())
        .send()
        .await?;
    assert_eq!(res.status(), 204);
    let res = client
        .delete(&url_practice)
        .headers(admin.clone())
        .send()
        .await?;
    assert_eq!(res.status(), 204);
    let res = client.get(&url_practice).headers(admin).send().await?;
    assert_eq!(res.status(), 404);

    Ok(())
}
