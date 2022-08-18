use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use notify::{watcher, DebouncedEvent, FsEventWatcher, RecursiveMode, Watcher};
use threadpool::ThreadPool;

mod scan;

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
}

type Err = String;

fn setup() -> Result<
    (
        Arc<scan::Engine>,
        FsEventWatcher,
        Receiver<DebouncedEvent>,
        ThreadPool,
    ),
    Err,
> {
    pretty_env_logger::init();

    let args = Arguments::parse();

    // initialize the scan engine
    let config = scan::Configuration {
        data_path: args.rules,
        timeout: args.scan_timeout,
    };
    let engine = Arc::new(scan::Engine::new(config).unwrap());

    // create a recursive filesystem monitor for the ROOT_PATH
    log::info!("initializing filesystem monitor for '{}' ...", &args.root);

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::ZERO).map_err(|e| e.to_string())?;

    watcher
        .watch(&args.root, RecursiveMode::Recursive)
        .map_err(|e| e.to_string())?;

    log::info!("initializing pool with {} workers ...", args.workers);

    let pool = ThreadPool::new(args.workers);

    Ok((engine, watcher, rx, pool))
}

fn main() {
    // initialize all the things!
    let (engine, _watcher, rx, pool) = setup().unwrap();

    log::info!("running ...");

    // receive filesystem events
    loop {
        match rx.recv() {
            Ok(event) => match event {
                // we're interested in files creation and modification
                DebouncedEvent::Create(path)
                | DebouncedEvent::NoticeWrite(path)
                | DebouncedEvent::Write(path)
                | DebouncedEvent::Rename(_, path) => {
                    // if it's a file and it exists
                    if path.is_file() && path.exists() {
                        // create a reference to the engine
                        // let r = rules.clone();
                        let an_engine = engine.clone();
                        // submit scan job to the threads pool
                        pool.execute(move || {
                            // perform the scanning
                            let res = an_engine.scan(&path);
                            if let Some(error) = res.error {
                                log::debug!("{:?}", error)
                            } else if res.detected {
                                log::warn!(
                                    "!!! MALWARE DETECTION: '{:?}' detected as '{:?}'",
                                    &path,
                                    res.tags.join(", ")
                                );
                            }
                        });
                    }
                }

                // ignored events
                DebouncedEvent::NoticeRemove(path) => {
                    log::trace!("ignoring remove event for {:?}", path);
                }
                DebouncedEvent::Chmod(path) => {
                    log::trace!("ignoring chmod event for {:?}", path);
                }
                DebouncedEvent::Remove(path) => {
                    log::trace!("ignoring remove event for {:?}", path);
                }
                // error events
                DebouncedEvent::Rescan => {
                    log::debug!("rescan");
                }
                DebouncedEvent::Error(error, maybe_path) => {
                    log::error!("error for {:?}: {:?}", maybe_path, error);
                }
            },
            Err(e) => log::error!("filesystem monitoring error: {:?}", e),
        }
    }
}
