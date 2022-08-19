use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
use threadpool::ThreadPool;

use crate::engine::Engine;
use crate::report::Report;
use crate::Arguments;

pub(crate) fn start(args: Arguments, engine: Engine, report: Report) -> Result<(), String> {
    // create a recursive filesystem monitor for the root path
    log::info!("initializing filesystem monitor for '{}' ...", &args.root);

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::ZERO).map_err(|e| e.to_string())?;

    watcher
        .watch(&args.root, RecursiveMode::Recursive)
        .map_err(|e| e.to_string())?;

    log::info!("initializing pool with {} workers ...", args.workers);

    let pool = ThreadPool::new(args.workers);

    log::info!("running ...");

    let engine = Arc::new(engine);
    let report = Arc::new(Mutex::new(report));

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
                        // create thread safe references
                        let engine = engine.clone();
                        let report = report.clone();
                        // submit scan job to the threads pool
                        pool.execute(move || {
                            // perform the scanning
                            let res = engine.scan(&path);
                            // handle reporting
                            if let Ok(mut report) = report.lock() {
                                if let Err(e) = report.report(res) {
                                    log::error!("reporting error: {:?}", e);
                                }
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
