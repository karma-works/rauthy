use crate::common::{get_auth_headers, get_backend_url};
use reqwest::Client;
use reqwest::multipart::{Form, Part};
use std::error::Error;

mod common;

const SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>"#;

/// The value of `<template id="tpl_client_logo_updated">` in a page
async fn logo_updated(client: &Client, url: &str) -> String {
    let html = client.get(url).send().await.unwrap().text().await.unwrap();
    let (_, rest) = html
        .split_once(r#"<template id="tpl_client_logo_updated">"#)
        .expect("tpl_client_logo_updated in the page");
    let (value, _) = rest.split_once("</template>").unwrap();
    value.to_string()
}

/// Pages that are not bound to a client show the `rauthy` logo, and cached pages pick up a new
/// one right away.
#[tokio::test]
async fn test_custom_logo_on_device_page() -> Result<(), Box<dyn Error>> {
    let backend = get_backend_url();
    let client = Client::new();
    let admin = get_auth_headers().await?;
    let url_device = format!("{backend}/device");
    let url_logo = format!("{backend}/clients/rauthy/logo");

    // fills the HTML cache
    let before = logo_updated(&client, &url_device).await;

    let form = Form::new().part(
        "logo",
        Part::bytes(SVG.as_bytes().to_vec())
            .file_name("logo.svg")
            .mime_str("image/svg+xml")?,
    );
    let res = client
        .put(&url_logo)
        .headers(admin.clone())
        .multipart(form)
        .send()
        .await?;
    assert!(res.status().is_success(), "{}", res.status());

    let after = logo_updated(&client, &url_device).await;
    assert!(!after.is_empty());
    assert_ne!(before, after, "the cached page must show the new logo");

    let res = client.delete(&url_logo).headers(admin).send().await?;
    assert!(res.status().is_success(), "{}", res.status());
    assert_eq!(logo_updated(&client, &url_device).await, "");

    Ok(())
}
