use crate::{cli::CliArgs, config::OKDConfig};
use anyhow::{Context, Result};
use clap::Parser;
use directories::ProjectDirs;
use log::{debug, error, info};
use oauth2::AccessToken;
use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{exit, Command},
};

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
    let config = match OKDConfig::from_dns(&config_host, cli.insecure_skip_tls_verify) {
        Ok(config) => config,
        Err(err) => {
            error!("Could not load config: {err}");
            exit(1);
        }
    };
    debug!("{config:#?}");

    let cache_dir = get_cache_dir();

    let okd_token = match oauth::get_okd_token(&config, &cache_dir) {
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

fn get_cache_dir() -> PathBuf {
    let project_dirs = ProjectDirs::from("", "", "oc-sso-login-rs").expect("HOME should be set");
    let cache_dir = project_dirs.cache_dir();
    debug!("Cache dir: {}", cache_dir.display());
    fs::create_dir_all(cache_dir).expect("Could not create cache dir");
    fs::set_permissions(cache_dir, Permissions::from_mode(0o700))
        .expect("Could not set cache dir permissions");
    cache_dir.to_path_buf()
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

    if config.insecure_skip_tls_verify {
        cmd.arg("--insecure-skip-tls-verify=true");
    }

    let status = cmd.status().context("Failed to execute `oc`")?;

    if !status.success() {
        anyhow::bail!("`oc login` failed, see above for error output");
    }

    Ok(())
}
