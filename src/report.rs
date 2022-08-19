use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;

use crate::engine::Detection;
use crate::Arguments;

type Error = String;

pub(crate) struct Report {
    args: Arguments,
    output: Option<File>,
    detections: Vec<Detection>,
}

impl Report {
    pub fn setup(args: &Arguments) -> Result<Self, Error> {
        let args = args.clone();
        let mut output = None;
        let detections = vec![];

        if let Some(output_file_name) = &args.report_output {
            output = Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output_file_name)
                    .map_err(|e| format!("can't create {:?}: {:?}", output_file_name, e))?,
            );
        }

        Ok(Self {
            args,
            output,
            detections,
        })
    }

    fn write_to_file_if_needed(
        &mut self,
        detection: Detection,
        message: String,
        to_json: Option<Detection>,
    ) -> Result<(), Error> {
        // if file reporting is enabled
        if let Some(output) = &mut self.output {
            let mut data = String::new();

            if self.args.report_json && to_json.is_some() {
                // JSON reporting is enabled and we have a detection to report
                self.detections.push(detection);
                // reset file
                output.set_len(0).map_err(|e| e.to_string())?;
                output.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                // serialize detections array, using format instead of whole object serialization
                // in order to borrow unmutable references to self
                data = format!(
                    "{{\"detections\":{}}}",
                    serde_json::to_string(&self.detections).map_err(|e| e.to_string())?
                );
            } else if !message.is_empty() {
                // plain text reporting
                data = format!("{}\n", &message);
            }

            // any data at all to write?
            if !data.is_empty() {
                // write to file
                output
                    .write_all(data.as_bytes())
                    .map_err(|e| e.to_string())?;
                // flush
                output.flush().map_err(|e| e.to_string())?;
            }
        }

        Ok(())
    }

    pub fn report(&mut self, detection: Detection) -> Result<(), Error> {
        let mut message = String::new();
        let mut to_json: Option<Detection> = None;

        if let Some(error) = &detection.error {
            log::debug!("{:?}", &error);

            if self.args.report_errors {
                message = error.to_owned();
                to_json = Some(detection.clone());

                log::error!("{}", &message);
            }
        } else if detection.detected {
            message = format!(
                "!!! MALWARE DETECTION: '{}' detected as '{:?}'",
                detection.path.to_string_lossy(),
                detection.tags.join(", ")
            );
            to_json = Some(detection.clone());

            log::warn!("{}", &message);
        } else if self.args.report_clean {
            message = format!("{} - clean", detection.path.to_string_lossy());
            to_json = Some(detection.clone());

            log::info!("{}", &message);
        }

        self.write_to_file_if_needed(detection, message, to_json)
    }
}
