use crate::config::OKDConfig;
use anyhow::Result;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Local, Utc};
use jsonwebtoken as jwt;
use log::{debug, error, info, trace, warn};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::url::ParseError;
use oauth2::{
    AccessToken, ClientId, DeviceAuthorizationUrl, RefreshToken,
    StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use reqwest::blocking::{Client, ClientBuilder};
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

static HTTP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

fn build_http_client(config: &OKDConfig) -> Client {
    ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(HTTP_USER_AGENT)
        .danger_accept_invalid_certs(config.insecure_skip_tls_verify)
        .danger_accept_invalid_hostnames(config.insecure_skip_tls_verify)
        .build()
        .expect("Client should build")
}

fn get_token_url(config: &OKDConfig) -> Result<TokenUrl, ParseError> {
    let base_url = config.auth_url.to_string();
    TokenUrl::new(format!("{base_url}/protocol/openid-connect/token"))
}

#[derive(Deserialize)]
struct JWTData {
    #[serde(with = "ts_seconds")]
    exp: DateTime<Utc>,
}

fn delete_cached_token(cache_file_path: &Path) {
    debug!("Deleting cache file: {}", cache_file_path.display());
    if let Err(err) = fs::remove_file(cache_file_path) {
        warn!("Deletion failed: {err}");
    }
}

fn get_cached_token(
    config: &OKDConfig,
    audience: &str,
    cache_dir: &Path,
    allow_refresh: bool,
) -> Option<AccessToken> {
    let cache_file_path = get_cache_file_path(audience, cache_dir);
    let token: BasicTokenResponse = {
        let f = File::open(&cache_file_path)
            .map_err(|err| info!("No cached {audience} token found: {err}"))
            .ok()?;
        serde_json::from_reader(f)
            .map_err(|err| warn!("Could not load cached {audience} token: {err}"))
            .ok()?
    };

    let access_token = token.access_token();
    info!("Loaded {audience} token from cache");
    let header = jwt::decode_header(access_token.secret()).expect("Could not decode JWT header");
    trace!("JWT header: {header:#?}");
    let key = jwt::DecodingKey::from_secret(&[]);
    let mut validation = jwt::Validation::new(header.alg);
    validation.insecure_disable_signature_validation();
    validation.set_audience(&[audience]);
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 10;
    match jwt::decode::<JWTData>(access_token.secret(), &key, &validation) {
        Ok(data) => {
            debug!(
                "Token expires at {}",
                data.claims.exp.with_timezone(&Local).to_rfc2822()
            );
            Some(access_token.to_owned())
        }
        Err(err) => match err.kind() {
            jwt::errors::ErrorKind::ExpiredSignature if !allow_refresh => {
                info!("Token expired, but refreshing is disabled");
                delete_cached_token(&cache_file_path);
                None
            }
            jwt::errors::ErrorKind::ExpiredSignature => {
                info!("Token expired, refreshing");
                let refresh_token = token.refresh_token()?;
                match use_refresh_token(config, audience, refresh_token) {
                    Ok(new_token) => {
                        info!("Used refresh token to get a new one");
                        save_cached_token(audience, cache_dir, &new_token);
                        Some(new_token.access_token().to_owned())
                    }
                    Err(err) => {
                        warn!("Could not refresh token: {err}");
                        delete_cached_token(&cache_file_path);
                        None
                    }
                }
            }
            jwt::errors::ErrorKind::InvalidAudience => {
                // we do not check the signature so this is not trustworthy,
                // but it's just for some more verbose logging anyway
                warn!("Token is for wrong audience");
                delete_cached_token(&cache_file_path);
                None
            }
            _ => {
                error!(
                    "Unexpeced JWT validation error: {kind:?}",
                    kind = err.kind()
                );
                delete_cached_token(&cache_file_path);
                None
            }
        },
    }
}

fn save_cached_token(audience: &str, cache_dir: &Path, token_result: &BasicTokenResponse) {
    let cache_file_path = get_cache_file_path(audience, cache_dir);
    let cache_file = OpenOptions::new()
        .mode(0o600)
        .write(true)
        .create(true)
        .truncate(true)
        .open(cache_file_path)
        .expect("Could not open cache file");
    serde_json::to_writer_pretty(cache_file, &token_result).expect("Token should be serializable");
}

fn get_cache_file_path(audience: &str, cache_dir: &Path) -> PathBuf {
    cache_dir.join(format!("sso_token_{audience}.json"))
}

fn use_refresh_token(
    config: &OKDConfig,
    audience: &str,
    refresh_token: &RefreshToken,
) -> Result<BasicTokenResponse> {
    let token_url = get_token_url(config)?;
    let client_id = ClientId::new(audience.to_string());
    let client = BasicClient::new(client_id).set_token_uri(token_url);
    let http_client = build_http_client(config);
    let token_result = client
        .exchange_refresh_token(refresh_token)
        .request(&http_client)?;
    Ok(token_result)
}

fn device_flow_login(config: &OKDConfig, cache_dir: &Path) -> Result<AccessToken> {
    if let Some(token) = get_cached_token(config, &config.login_application_id, cache_dir, true) {
        return Ok(token);
    }

    let base_url = config.auth_url.to_string();
    let device_auth_url =
        DeviceAuthorizationUrl::new(format!("{base_url}/protocol/openid-connect/auth/device"))?;
    let token_url = get_token_url(config)?;
    let client_id = ClientId::new(config.login_application_id.to_string());
    let client = BasicClient::new(client_id)
        .set_device_authorization_url(device_auth_url)
        .set_token_uri(token_url);

    let http_client = build_http_client(config);

    let details: StandardDeviceAuthorizationResponse =
        client.exchange_device_code().request(&http_client)?;

    eprintln!(
        "Open this link in your browser and enter the code: {}\n{}",
        details.user_code().secret(),
        details.verification_uri(),
    );

    if let Some(verification_uri_complete) = details.verification_uri_complete() {
        eprintln!(
            "\nYou may also use this link to avoid entering the code manually:\n{}",
            verification_uri_complete.secret()
        );
    }

    let token_result = client.exchange_device_access_token(&details).request(
        &http_client,
        std::thread::sleep,
        None,
    )?;

    save_cached_token(&config.login_application_id, cache_dir, &token_result);
    Ok(token_result.access_token().to_owned())
}

fn exchange_oauth_token(
    config: &OKDConfig,
    cache_dir: &Path,
    token: &AccessToken,
) -> Result<AccessToken> {
    if let Some(token) = get_cached_token(config, &config.audience_id, cache_dir, false) {
        return Ok(token);
    }

    let token_url = get_token_url(config)?;
    let http_client = build_http_client(config);
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
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        anyhow::bail!("SSO token exchange failed ({}): {}", status, text);
    }
    let deserialized_token =
        serde_json::from_str::<BasicTokenResponse>(&text).expect("Could not parse token");
    save_cached_token(&config.audience_id, cache_dir, &deserialized_token);
    Ok(deserialized_token.access_token().to_owned())
}

#[derive(Deserialize)]
struct OKDTokenResponse {
    token: AccessToken,
}

fn exchange_okd_token(config: &OKDConfig, token: &AccessToken) -> Result<AccessToken> {
    let base_url = config.token_exchange_url.to_string();
    let api_url = format!("{base_url}/openshift-api-token");
    let http_client = build_http_client(config);
    let response = http_client
        .get(api_url)
        .bearer_auth(token.secret())
        .query(&[("redirect-uri", "http://localhost")]) // dummy value required by the API
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        anyhow::bail!("OKD token exchange failed ({}): {}", status, text);
    }
    let deserialized_token: OKDTokenResponse = serde_json::from_str(&text)?;
    Ok(deserialized_token.token)
}

pub fn get_okd_token(config: &OKDConfig, cache_dir: &Path) -> Result<AccessToken> {
    let cluster_app_token = match get_cached_token(config, &config.audience_id, cache_dir, false) {
        // If we have a valid token for the OKD cluster, we don't care about the login app token
        Some(cluster_app_token) => cluster_app_token,
        // Do the normal flow of getting an SSO token (device flow) and exchanging it
        None => {
            let login_app_token = device_flow_login(config, cache_dir)?;
            exchange_oauth_token(config, cache_dir, &login_app_token)?
        }
    };
    info!("Requesting OKD token");
    let okd_token = exchange_okd_token(config, &cluster_app_token)?;
    Ok(okd_token)
}
