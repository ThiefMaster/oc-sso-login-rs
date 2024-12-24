use crate::config::OKDConfig;
use crate::cli::CliArgs;
use clap::Parser;
use log::{debug, error, info};
use std::process::exit;

mod config;
mod cli;

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
}
