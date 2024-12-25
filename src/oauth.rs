use anyhow::Result;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::url::ParseError;
use oauth2::{
    AccessToken, ClientId, DeviceAuthorizationUrl, StandardDeviceAuthorizationResponse,
    TokenResponse, TokenUrl,
};
use reqwest::blocking::{Client, ClientBuilder};
use serde::Deserialize;

use crate::config::OKDConfig;

fn build_http_client() -> Client {
    ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build")
}

fn get_token_url(config: &OKDConfig) -> Result<TokenUrl, ParseError> {
    let base_url = config.auth_url.to_string();
    TokenUrl::new(format!("{base_url}/protocol/openid-connect/token"))
}

fn device_flow_login(config: &OKDConfig) -> Result<AccessToken> {
    let base_url = config.auth_url.to_string();
    let device_auth_url =
        DeviceAuthorizationUrl::new(format!("{base_url}/protocol/openid-connect/auth/device"))?;
    let token_url = get_token_url(config)?;
    let client_id = ClientId::new(config.login_application_id.to_string());
    let client = BasicClient::new(client_id)
        .set_device_authorization_url(device_auth_url)
        .set_token_uri(token_url);

    let http_client = build_http_client();

    let details: StandardDeviceAuthorizationResponse =
        client.exchange_device_code().request(&http_client)?;

    eprintln!(
        "Open this link in your browser and enter the code: {}\n{}",
        details.user_code().secret(),
        details.verification_uri(),
    );

    eprintln!(
        "\nYou may also use this link to avoid entering the code manually:\n{}",
        details.verification_uri_complete().unwrap().secret()
    );

    let token_result = client.exchange_device_access_token(&details).request(
        &http_client,
        std::thread::sleep,
        None,
    )?;

    Ok(token_result.access_token().to_owned())
}

fn exchange_oauth_token(config: &OKDConfig, token: &AccessToken) -> Result<AccessToken> {
    let token_url = get_token_url(config)?;
    let http_client = build_http_client();
    let response = http_client
        .post(token_url.to_string())
        .form(&[
            ("client_id", &config.login_application_id),
            ("audience", &config.audience_id),
            (
                "grant_type",
                &"urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ),
            (
                "requested_token_type",
                &"urn:ietf:params:oauth:token-type:refresh_token".to_string(),
            ),
            ("subject_token", token.secret()),
        ])
        .send()?;
    response.error_for_status_ref()?;
    let serialized_json = response.text()?;
    let deserialized_token = serde_json::from_str::<BasicTokenResponse>(&serialized_json).unwrap();
    Ok(deserialized_token.access_token().to_owned())
}

#[derive(Deserialize)]
struct OKDTokenResponse {
    token: AccessToken,
}

fn exchange_okd_token(config: &OKDConfig, token: &AccessToken) -> Result<AccessToken> {
    let base_url = config.token_exchange_url.to_string();
    let api_url = format!("{base_url}/openshift-api-token");
    let http_client = build_http_client();
    let response = http_client
        .get(api_url)
        .bearer_auth(token.secret())
        .query(&[("redirect-uri", "http://localhost")]) // dummy value required by the API
        .send()?;
    response.error_for_status_ref()?;
    let serialized_json = &response.text()?;
    let deserialized_token: OKDTokenResponse = serde_json::from_str(serialized_json)?;
    Ok(deserialized_token.token)
}

pub fn get_okd_token(config: &OKDConfig) -> Result<AccessToken> {
    let login_app_token = device_flow_login(config)?;
    let cluster_app_token = exchange_oauth_token(config, &login_app_token)?;
    let okd_token = exchange_okd_token(config, &cluster_app_token)?;
    Ok(okd_token)
}
