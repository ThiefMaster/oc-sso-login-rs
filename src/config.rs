use domain::base::{iana::Rcode, Rtype};
use domain::resolv::StubResolver;
use domain::{base::name::Name, rdata::Txt};
use log::{trace, warn};
use std::{collections::HashMap, str::FromStr};

#[derive(Debug)]
pub struct OKDConfig {
    pub insecure_skip_tls_verify: bool,
    pub token_exchange_url: String,
    pub auth_url: String,
    pub audience_id: String,
    pub login_application_id: String,
    pub api_url: String,
}

impl OKDConfig {
    fn from_map(
        map: &HashMap<String, String>,
        insecure_skip_tls_verify: bool,
    ) -> Result<Self, &'static str> {
        let Some(token_exchange_url) = map.get("token_exchange_url") else {
            return Err("Missing token_exchange_url");
        };
        let Some(auth_url) = map.get("auth_url") else {
            return Err("Missing auth_url");
        };
        let Some(audience_id) = map.get("audience_id") else {
            return Err("Missing audience_id");
        };
        let Some(login_application_id) = map.get("login_application_id") else {
            return Err("Missing login_application_id");
        };
        let Some(api_url) = map.get("api_url") else {
            return Err("Missing api_url");
        };
        if !auth_url.starts_with("https://") {
            return Err("Auth URL does not start with https://");
        }
        if !api_url.starts_with("https://") {
            return Err("API URL does not start with https://");
        }
        if !api_url.ends_with(".cern.ch") {
            return Err("API URL does not end with .cern.ch");
        }
        if !token_exchange_url.starts_with("https://") {
            return Err("Token Exchange URL does not start with https://");
        }
        if !token_exchange_url.ends_with(".cern.ch") {
            return Err("Token Exchange URL does not end with .cern.ch");
        }
        if audience_id.is_empty() {
            return Err("Empty audience ID");
        }
        if login_application_id.is_empty() {
            return Err("Empty login application ID");
        }
        Ok(Self {
            insecure_skip_tls_verify,
            token_exchange_url: token_exchange_url.to_string(),
            auth_url: auth_url.to_string(),
            audience_id: audience_id.to_string(),
            login_application_id: login_application_id.to_string(),
            api_url: api_url.to_string(),
        })
    }

    pub fn from_dns(
        config_host: &str,
        insecure_skip_tls_verify: bool,
    ) -> Result<Self, &'static str> {
        let name = Name::<Vec<_>>::from_str(config_host).unwrap();
        let res =
            StubResolver::run(move |stub| async move { stub.query((name, Rtype::TXT)).await });
        let res = res.unwrap();
        let rcode = res.header().rcode();

        if rcode != Rcode::NOERROR {
            warn!("DNS lookup rcode: {rcode}");
            return Err("DNS lookup failed");
        }

        let answer = res.answer().unwrap();
        if answer.count() == 0 {
            return Err("No DNS records found");
        }

        let config: HashMap<String, String> = answer
            // make sure we only have TXT records
            .limit_to::<Txt<_>>()
            // convert them to strings
            .map(|rec| rec.unwrap().data().to_string())
            // split them into key, value tuples
            .map(|line| {
                let (k, v) = line.trim_matches('"').split_once('=').unwrap();
                (k.trim().to_string(), v.trim().to_string())
            })
            .collect();

        trace!("Data from DNS: {config:?}");
        Self::from_map(&config, insecure_skip_tls_verify)
    }
}
