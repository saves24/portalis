//! Machine-readable progress for the callers that embed this binary.
//!
//! With `PORTALIS_JSON` set, every stage of a long command is one JSON object per
//! line on stdout, and the human lines go to stderr.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turns the event stream on or off.
pub fn enable(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Answers whether events are being printed.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

fn emit(value: Value) {
    if enabled() {
        println!("{value}");
    }
}

/// One stage of a long command.
pub fn phase(stage: &str, package: &str, version: &str) {
    emit(json!({
        "event": "phase",
        "phase": stage,
        "package": package,
        "version": version,
    }));
}

/// The command finished; the fields describe what it left behind.
pub fn done(fields: Value) {
    let mut value = json!({ "event": "done" });
    if let (Some(object), Some(extra)) = (value.as_object_mut(), fields.as_object()) {
        for (key, item) in extra {
            object.insert(key.clone(), item.clone());
        }
    }
    emit(value);
}

/// The command failed, with the code the failure carries.
pub fn fail(error: &anyhow::Error) {
    emit(json!({
        "event": "error",
        "code": crate::error::code_of(error).as_str(),
        "message": format!("{error:#}"),
    }));
}

/// Prints a result line: stdout normally, stderr while events are on.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {
        if $crate::json::enabled() {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    };
}
