use clap::Parser;

mod engine;
mod fs_monitor;
mod fs_scan;

#[derive(Parser, Default, Debug)]
#[clap(
    about = "Minimalistic cross-platform filesystem monitor and malware scanner using YARA rules."
)]
struct Arguments {
    /// Root path of the filesystem to monitor.
    #[clap(long, default_value = "/")]
    root: String,
    /// Path of YARA rules to use.
    #[clap(long)]
    rules: String,
    /// Number of worker threads used for scanning.
    #[clap(long, default_value_t = 32)]
    workers: usize,
    /// Scan timeout in seconds.
    #[clap(long, default_value_t = 30)]
    scan_timeout: i32,
    /// Perform a scan of every file in the specified root folder and exit.
    #[clap(long, takes_value = false)]
    scan: bool,
    /// Only scan files with the specified extension if --scan is used, can be passed multiple times.
    #[clap(long)]
    ext: Vec<String>,
}

fn main() -> Result<(), String> {
    pretty_env_logger::init();

    let args = Arguments::parse();

    // initialize the scan engine
    let config = engine::Configuration {
        data_path: args.rules.clone(),
        timeout: args.scan_timeout,
    };
    let engine = engine::Engine::new(config)?;

    if args.scan {
        // perform a scan of the root folder and exit
        fs_scan::start(args, engine)
    } else {
        // monitor the filesystem
        fs_monitor::start(args, engine)
    }
}
