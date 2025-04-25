// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Errors that might be seen when creating a core dump file.

use thiserror::Error;

/// Error encountered during creating a core dump file
#[derive(Debug, Error)]
pub enum CoreError {
    /// Race when seizingg threads
    #[error("race when seizing threads")]
    RaceTryAgain,
    /// A process cannot dump itself
    #[error("cannot create a core dump file for the process itself")]
    CantDumpItself,
    /// An error related to the provided [`ProcessInfoSource`]
    #[error("cannot create a core dump file for custom process info source")]
    CustomSourceInfo,
    /// A /proc file parsing error
    #[error("/proc parsing error")]
    ProcParsingError,
    /// A /proc file parsing error
    #[error("/proc integer parsing error")]
    ProcIntParsingError(#[from] std::num::ParseIntError),
    /// Internal error
    #[error("internal error: {0}")]
    InternalError(&'static str),
    /// OS error
    #[error("OS error")]
    NixError(#[from] nix::Error),
    /// I/O error
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
}
