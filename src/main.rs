use crate::{cli::CliArgs, config::OKDConfig};
use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info};
use oauth2::AccessToken;
use std::process::{exit, Command};

mod cli;
mod config;
mod oauth;

fn main() {
    let cli = CliArgs::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbosity.into())
        .init();

    let cluster = cli.cluster;
    info!("Using cluster {cluster}",);
    let config_host = format!("_config.{cluster}.okd.cern.ch");

    debug!("Querying config data from {config_host}");
    let config = match OKDConfig::from_dns(&config_host) {
        Ok(config) => config,
        Err(err) => {
            error!("Could not load config: {err}");
            exit(1);
        }
    };
    debug!("{config:#?}");

    let okd_token = match oauth::get_okd_token(&config) {
        Ok(token) => token,
        Err(err) => {
            error!("Could not get token: {err:#}");
            exit(1);
        }
    };
    if let Err(err) = oc_login(&config, &okd_token) {
        error!("Could not login to OKD: {err:#}");
        exit(1);
    }
}

fn oc_login(config: &OKDConfig, token: &AccessToken) -> Result<()> {
    let mut cmd = Command::new("oc");
    cmd.args([
        "login",
        "--server",
        &config.api_url,
        "--token",
        token.secret(),
    ]);

    let status = cmd.status().context("Failed to execute `oc`")?;

    if !status.success() {
        anyhow::bail!("`oc login` failed, see above for error output");
    }

    Ok(())
}
