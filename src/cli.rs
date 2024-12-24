use clap::builder::{
    styling::{AnsiColor, Effects},
    Styles,
};
use clap::Parser;
use clap_verbosity_flag::Verbosity;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = STYLES)]
pub struct CliArgs {
    /// Friendly name of a CERN OKD4 cluster
    #[arg(default_value = "paas")]
    pub cluster: String,

    /// Enable verbose output
    #[command(flatten)]
    pub verbosity: Verbosity,
}
