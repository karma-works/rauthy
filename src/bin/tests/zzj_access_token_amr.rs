use crate::common::{
    PASSWORD, USERNAME, decode_claims, get_auth_headers, get_backend_url, get_solved_pow,
    session_headers_for_client, session_headers_with,
};
use pretty_assertions::assert_eq;
use rauthy_api_types::clients::{ClientSecretResponse, NewClientRequest, UpdateClientRequest};
use rauthy_api_types::oidc::{
    DeviceAcceptedRequest, DeviceGrantRequest, DeviceVerifyRequest, GrantType, JwkKeyPairAlg,
    TokenRequest, TokenType,
};
use rauthy_service::token_set::TokenSet;
use std::error::Error;
use std::time::Duration;
use tokio::time;

mod common;

const ID: &str = "amr_access_test";

/// Asserts the access token carries the same `amr` / `auth_time` as the id token of the same
/// token set and returns the `auth_time`. Without any MFA ceremony, `amr` must be `["pwd"]`.
fn assert_user_authentication(ts: &TokenSet) -> i64 {
    let access = decode_claims(&ts.access_token);
    let id = decode_claims(ts.id_token.as_deref().expect("an id token"));

    assert_eq!(access["amr"], serde_json::json!(["pwd"]));
    assert_eq!(access["amr"], id["amr"]);
    let auth_time = access["auth_time"]
        .as_i64()
        .expect("`auth_time` in the access token");
    assert_eq!(Some(auth_time), id["auth_time"].as_i64());
    auth_time
}

async fn refresh(
    http: &reqwest::Client,
    secret: &str,
    refresh_token: &str,
) -> Result<TokenSet, Box<dyn Error>> {
    let res = http
        .post(format!("{}/oidc/token", get_backend_url()))
        .form(&TokenRequest {
            grant_type: GrantType::RefreshToken,
            client_id: Some(ID.to_string()),
            client_secret: Some(secret.to_string()),
            refresh_token: Some(refresh_token.to_string()),
            ..Default::default()
        })
        .send()
        .await?;
    assert_eq!(res.status(), 200, "{}", res.text().await?);
    Ok(res.json::<TokenSet>().await?)
}

/// `amr` and `auth_time` are part of every user access token, are derived exactly like in the
/// id token, survive a refresh unchanged, and never show up for `client_credentials`.
#[tokio::test]
async fn test_access_token_amr_auth_time() -> Result<(), Box<dyn Error>> {
    let auth_headers = get_auth_headers().await?;
    let backend_url = get_backend_url();
    let http = reqwest::Client::new();
    let redirect_uri = format!("{backend_url}/oidc/callback");

    let res = http
        .post(format!("{backend_url}/clients"))
        .headers(auth_headers.clone())
        .json(&NewClientRequest {
            id: ID.to_string(),
            secret: None,
            name: Some("amr access token test".to_string()),
            confidential: true,
            redirect_uris: vec![redirect_uri.clone()],
            post_logout_redirect_uris: None,
        })
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    let res = http
        .put(format!("{backend_url}/clients/{ID}"))
        .headers(auth_headers.clone())
        .json(&UpdateClientRequest {
            name: Some("amr access token test".to_string()),
            confidential: true,
            redirect_uris: vec![redirect_uri.clone()],
            post_logout_redirect_uris: None,
            allowed_origins: None,
            enabled: true,
            flows_enabled: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::DeviceCode,
                GrantType::Password,
                GrantType::RefreshToken,
                GrantType::TokenExchange,
            ],
            access_token_alg: JwkKeyPairAlg::RS256,
            id_token_alg: JwkKeyPairAlg::RS256,
            auth_code_lifetime: 60,
            // 60 seconds makes the refresh token valid immediately in the test config
            access_token_lifetime: 60,
            scopes: vec!["openid".to_string(), "email".to_string()],
            default_scopes: vec!["openid".to_string()],
            challenges: Some(vec!["S256".to_string()]),
            force_mfa: false,
            client_uri: None,
            contacts: None,
            backchannel_logout_uri: None,
            restrict_group_prefix: None,
            claims: None,
            claims_at_root: false,
            allowed_resources: None,
            default_aud: None,
            scim: None,
        })
        .send()
        .await?;
    assert_eq!(res.status(), 200, "{}", res.text().await?);

    let res = http
        .post(format!("{backend_url}/clients/{ID}/secret"))
        .headers(auth_headers.clone())
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let secret = res.json::<ClientSecretResponse>().await?.secret.unwrap();

    // (1) authorization code with PKCE
    let (_, ts) = session_headers_for_client(ID, Some(&secret), &redirect_uri).await;
    let auth_time = assert_user_authentication(&ts);

    // (2) a refresh keeps the original `amr` and `auth_time`, it is no new authentication
    time::sleep(Duration::from_millis(1100)).await;
    let ts_refreshed = refresh(&http, &secret, ts.refresh_token.as_deref().unwrap()).await?;
    assert_ne!(ts.access_token, ts_refreshed.access_token);
    assert_eq!(assert_user_authentication(&ts_refreshed), auth_time);

    // (3) device authorization grant, approved by a browser session
    let res = http
        .post(format!("{backend_url}/oidc/device"))
        .form(&DeviceGrantRequest {
            client_id: ID.to_string(),
            client_secret: Some(secret.clone()),
            scope: Some("openid".to_string()),
            nonce: None,
        })
        .send()
        .await?;
    assert_eq!(res.status(), 200, "{}", res.text().await?);
    let device_res = res.json::<serde_json::Value>().await?;
    let device_code = device_res["device_code"].as_str().unwrap().to_string();
    let user_code = device_res["user_code"].as_str().unwrap().to_string();

    let session = session_headers_with(USERNAME, PASSWORD).await;
    let res = http
        .post(format!("{backend_url}/oidc/device/verify"))
        .headers(session)
        .json(&DeviceVerifyRequest {
            user_code,
            pow: get_solved_pow().await,
            device_accepted: DeviceAcceptedRequest::Accept,
        })
        .send()
        .await?;
    assert_eq!(res.status(), 202, "{}", res.text().await?);

    let before_device_token = chrono::Utc::now().timestamp();
    let ts_device = {
        let mut attempts = 0;
        loop {
            let res = http
                .post(format!("{backend_url}/oidc/token"))
                .form(&TokenRequest {
                    grant_type: GrantType::DeviceCode,
                    client_id: Some(ID.to_string()),
                    client_secret: Some(secret.clone()),
                    device_code: Some(device_code.clone()),
                    ..Default::default()
                })
                .send()
                .await?;
            if res.status() == 200 {
                break res.json::<TokenSet>().await?;
            }
            // the device grant enforces its poll interval
            let body = res.text().await?;
            attempts += 1;
            assert!(attempts < 5, "device token not issued: {body}");
            assert!(body.contains("slow_down"), "unexpected error: {body}");
            time::sleep(Duration::from_secs(5)).await;
        }
    };
    let device_claims = decode_claims(&ts_device.access_token);
    assert!(device_claims["did"].is_string(), "a device token");
    let device_auth_time = assert_user_authentication(&ts_device);
    // the device flow uses the time of token issuance, like its id token
    assert!(device_auth_time >= before_device_token - 1);

    // (4) a device refresh keeps them as well
    time::sleep(Duration::from_millis(1100)).await;
    let ts_device_refreshed =
        refresh(&http, &secret, ts_device.refresh_token.as_deref().unwrap()).await?;
    assert!(decode_claims(&ts_device_refreshed.access_token)["did"].is_string());
    assert_eq!(
        assert_user_authentication(&ts_device_refreshed),
        device_auth_time
    );

    // (5) a token exchange represents the subject and keeps its authentication
    let res = http
        .post(format!("{backend_url}/oidc/token"))
        .form(&TokenRequest {
            grant_type: GrantType::TokenExchange,
            client_id: Some(ID.to_string()),
            client_secret: Some(secret.clone()),
            subject_token: Some(ts.access_token.clone()),
            subject_token_type: Some(TokenType::AccessToken.to_string()),
            ..Default::default()
        })
        .send()
        .await?;
    assert_eq!(res.status(), 200, "{}", res.text().await?);
    let exchanged = decode_claims(&res.json::<TokenSet>().await?.access_token);
    assert_eq!(exchanged["amr"], serde_json::json!(["pwd"]));
    assert_eq!(exchanged["auth_time"].as_i64(), Some(auth_time));

    // (6) `client_credentials` has no user and therefore no user authentication
    let res = http
        .post(format!("{backend_url}/oidc/token"))
        .form(&TokenRequest {
            grant_type: GrantType::ClientCredentials,
            client_id: Some(ID.to_string()),
            client_secret: Some(secret.clone()),
            ..Default::default()
        })
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let cc = decode_claims(&res.json::<TokenSet>().await?.access_token);
    assert!(
        cc.get("amr").is_none(),
        "client_credentials must not carry `amr`"
    );
    assert!(
        cc.get("auth_time").is_none(),
        "client_credentials must not carry `auth_time`"
    );

    let res = http
        .delete(format!("{backend_url}/clients/{ID}"))
        .headers(auth_headers)
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    Ok(())
}
