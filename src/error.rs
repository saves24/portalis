//! The codes the JSON stream reports, and the errors that carry them.

use anyhow::Error;
use std::fmt;

/// What went wrong, in the vocabulary callers of the event stream know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    ShaMismatch,
    ReadOnlyRoot,
    LockTimeout,
    DiskFull,
    SignatureRequired,
    RecipeInvalid,
    ConflictUnmanaged,
    InputMissing,
    RecoveryBlocked,
    Internal,
}

impl Code {
    /// The name a caller reads in the `code` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShaMismatch => "SHA_MISMATCH",
            Self::ReadOnlyRoot => "READ_ONLY_ROOT",
            Self::LockTimeout => "LOCK_TIMEOUT",
            Self::DiskFull => "DISK_FULL",
            Self::SignatureRequired => "SIGNATURE_REQUIRED",
            Self::RecipeInvalid => "RECIPE_INVALID",
            Self::ConflictUnmanaged => "CONFLICT_UNMANAGED",
            Self::InputMissing => "INPUT_MISSING",
            Self::RecoveryBlocked => "RECOVERY_BLOCKED",
            Self::Internal => "INTERNAL",
        }
    }
}

/// An error that knows its code.
#[derive(Debug)]
pub struct Coded {
    code: Code,
    detail: String,
}

impl Coded {
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn code(&self) -> Code {
        self.code
    }
}

impl fmt::Display for Coded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for Coded {}

/// The code of a failure: the first coded error in the chain wins, then the
/// kind of the first failed system call, and anything else is internal.
pub fn code_of(error: &Error) -> Code {
    for cause in error.chain() {
        if let Some(coded) = cause.downcast_ref::<Coded>() {
            return coded.code();
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if let Some(code) = from_errno(io) {
                return code;
            }
        }
    }
    Code::Internal
}

/// The code of a failed system call, for the ones callers act on.
fn from_errno(error: &std::io::Error) -> Option<Code> {
    match error.raw_os_error() {
        Some(libc::ENOSPC) => Some(Code::DiskFull),
        Some(libc::EROFS) => Some(Code::ReadOnlyRoot),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn a_coded_failure_keeps_its_code_through_context() {
        let failure = || -> anyhow::Result<()> {
            Err(Coded::new(Code::SignatureRequired, "no trusted key signed it").into())
        };
        let error = failure()
            .context("installing hello")
            .expect_err("the failure was swallowed");
        assert_eq!(code_of(&error), Code::SignatureRequired);
    }

    #[test]
    fn a_message_alone_decides_nothing() {
        let error = anyhow::anyhow!("signature of the recipe does not matter here");
        assert_eq!(
            code_of(&error),
            Code::Internal,
            "a word in the message was read as a code"
        );
    }

    #[test]
    fn a_failed_system_call_reports_what_callers_act_on() {
        let full = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(code_of(&full), Code::DiskFull);
        let read_only = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EROFS));
        assert_eq!(code_of(&read_only), Code::ReadOnlyRoot);
        let missing = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(
            code_of(&missing),
            Code::Internal,
            "a bare ENOENT was given a code of its own"
        );
    }
}
