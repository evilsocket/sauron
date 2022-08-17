use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use notify::{watcher, DebouncedEvent, FsEventWatcher, RecursiveMode, Watcher};
use threadpool::ThreadPool;
use walkdir::WalkDir;
use yara::{Compiler, Rules};

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
        Arguments,
        Arc<Rules>,
        FsEventWatcher,
        Receiver<DebouncedEvent>,
        ThreadPool,
    ),
    Err,
> {
    pretty_env_logger::init();

    let args = Arguments::parse();

    // create YARA compiler
    let mut compiler = Compiler::new().map_err(|e| e.to_string())?;
    let mut num_rules = 0;

    log::info!("loading yara rules from '{}' ...", &args.rules);

    // a single yara file has been passed as argument
    if args.rules.ends_with(".yar") {
        log::debug!("loading {} ...", &args.rules);
        compiler = compiler
            .add_rules_file(&args.rules)
            .map_err(|e| format!("could not load {:?}: {:?}", &args.rules, e))?;
        num_rules += 1;
    } else {
        // loop rules folder and load each .yar file
        for entry in WalkDir::new(&args.rules)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let f_name = entry.path().to_string_lossy();

            if f_name.ends_with(".yar") {
                log::debug!("loading {} ...", &f_name);
                compiler = compiler
                    .add_rules_file(&*f_name)
                    .map_err(|e| format!("could not load {:?}: {:?}", f_name, e))?;
                num_rules += 1;
            }
        }
    }

    // compile all rules
    log::debug!("compiling {} rules ...", num_rules);

    let start = Instant::now();

    let rules = Arc::new(compiler.compile_rules().map_err(|e| e.to_string())?);

    log::info!("{} rules compiled in {:?}", num_rules, start.elapsed());

    // create a recursive filesystem monitor for the ROOT_PATH
    log::info!("initializing filesystem monitor for '{}' ...", &args.root);

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::ZERO).map_err(|e| e.to_string())?;

    watcher
        .watch(&args.root, RecursiveMode::Recursive)
        .map_err(|e| e.to_string())?;

    log::info!("initializing pool with {} workers ...", args.workers);

    let pool = ThreadPool::new(args.workers);

    Ok((args, rules, watcher, rx, pool))
}

fn main() {
    // initialize all the things!
    let (args, rules, _watcher, rx, pool) = setup().unwrap();

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
                        // create a reference to the YARA rules and submit scan job to the threads pool
                        let r = rules.clone();
                        pool.execute(move || {
                            // get file metadata
                            match std::fs::metadata(&path) {
                                Ok(meta) => {
                                    // skip empty files
                                    let file_size = meta.len();
                                    if file_size == 0 {
                                        log::trace!("ignoring empty file {:?}", &path);
                                    } else {
                                        log::debug!("scanning {:?} ({} bytes)", &path, file_size);
                                        // scan this file with the loaded YARA rules
                                        match r.scan_file(&path, args.scan_timeout) {
                                            Ok(res) => {
                                                // do we have any detection?
                                                if res.len() > 0 {
                                                    let detections = res
                                                        .iter()
                                                        .map(|x| x.identifier)
                                                        .collect::<Vec<&str>>();

                                                    log::warn!(
                                                        "!!! MALWARE DETECTION: '{:?}' detected as '{:?}'",
                                                        &path,
                                                        detections.join(", ")
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!("error scanning '{:?}': {:?}", &path, e)
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::debug!("error getting '{:?}' metadata: {:?}", &path, e)
                                }
                            }});
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
