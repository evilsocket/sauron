use std::path::PathBuf;

use crate::engine::Detection;

pub(crate) fn report(path: &PathBuf, detection: Detection) {
    if let Some(error) = detection.error {
        log::debug!("{:?}", error)
    } else if detection.detected {
        log::warn!(
            "!!! MALWARE DETECTION: '{:?}' detected as '{:?}'",
            &path,
            detection.tags.join(", ")
        );
    }
}
