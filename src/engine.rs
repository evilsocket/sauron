use std::path::PathBuf;
use std::time::Instant;

use walkdir::WalkDir;
use yara::{Compiler, Rules};

pub type Error = String;
pub type Tag = String;

#[derive(Clone, Debug)]
pub struct Detection {
    pub error: Option<Error>,
    pub detected: bool,
    pub tags: Vec<Tag>,
}

pub struct Configuration {
    pub data_path: String,
    pub timeout: i32,
}

pub struct Engine {
    config: Configuration,
    rules: Rules,
}

impl Engine {
    pub fn new(config: Configuration) -> Result<Self, Error> {
        log::info!("initializing yara engine from '{}' ...", &config.data_path);

        // create YARA compiler
        let mut compiler = Compiler::new().map_err(|e| e.to_string())?;
        let mut num_rules = 0;

        // a single yara file has been passed as argument
        if config.data_path.ends_with(".yar") {
            log::debug!("loading {} ...", &config.data_path);
            compiler = compiler
                .add_rules_file(&config.data_path)
                .map_err(|e| format!("could not load {:?}: {:?}", &config.data_path, e))?;
            num_rules += 1;
        } else {
            // loop rules folder and load each .yar file
            for entry in WalkDir::new(&config.data_path)
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

        let rules = compiler.compile_rules().map_err(|e| e.to_string())?;

        log::info!("{} rules compiled in {:?}", num_rules, start.elapsed());

        Ok(Engine { config, rules })
    }

    pub fn scan(&self, path: &PathBuf) -> Detection {
        let mut detected = false;
        let mut tags = vec![];
        let mut error: Option<Error> = None;

        // get file metadata
        match std::fs::metadata(&path) {
            Ok(data) => {
                // skip empty files
                let file_size = data.len();
                if file_size == 0 {
                    log::trace!("ignoring empty file {:?}", &path);
                } else {
                    let start = Instant::now();

                    // scan this file with the loaded YARA rules
                    match self.rules.scan_file(path, self.config.timeout) {
                        Ok(matches) => {
                            if !matches.is_empty() {
                                detected = true;
                                for rule in matches {
                                    tags.push(rule.identifier.to_string());
                                }
                            }
                        }
                        Err(e) => error = Some(format!("can't scan {:?}: {:?}", path, e)),
                    }

                    log::debug!(
                        "{:?} - {} bytes scanned in {:?} ",
                        path,
                        file_size,
                        start.elapsed()
                    );
                }
            }
            Err(e) => error = Some(format!("can't get metadata for {:?}: {:?}", path, e)),
        }

        Detection {
            detected,
            tags,
            error,
        }
    }
}
