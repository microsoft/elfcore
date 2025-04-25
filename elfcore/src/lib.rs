// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A Rust library for creating ELF core dump files.

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

mod arch;
mod coredump;
mod elf;
mod error;
mod linux;

pub use coredump::write_core_dump;
pub use coredump::CoreDumpBuilder;
pub use error::CoreError;
pub use linux::process::ProcessView;
