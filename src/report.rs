use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

use crate::engine::Detection;
use crate::Arguments;

type Error = String;

pub(crate) struct Report {
    args: Arguments,
    output: Option<File>,
}

impl Report {
    pub fn setup(args: &Arguments) -> Result<Self, Error> {
        let args = args.clone();
        let mut output = None;

        if let Some(output_file_name) = &args.report_output {
            output = Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output_file_name)
                    .map_err(|e| e.to_string())?,
            );
        }

        Ok(Self { args, output })
    }

    pub fn report(&mut self, path: &Path, detection: Detection) -> Result<(), Error> {
        let mut message = String::new();

        if let Some(error) = detection.error {
            log::debug!("{:?}", &error);
            if self.args.report_errors {
                message = error;
                log::error!("{}", &message);
            }
        } else if detection.detected {
            message = format!(
                "!!! MALWARE DETECTION: '{}' detected as '{:?}'",
                path.to_string_lossy(),
                detection.tags.join(", ")
            );
            log::warn!("{}", &message);
        } else if self.args.report_clean {
            message = format!("{} - clean", path.to_string_lossy());
            log::info!("{}", &message);
        }

        if !message.is_empty() {
            if let Some(output) = &mut self.output {
                output
                    .write_all(format!("{}\n", &message).as_bytes())
                    .map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
            }
        }

        Ok(())
    }
}
