//! This module contains the functionality for
//! gathering process information on Linux systems.

mod memory;
mod process;
pub mod ptrace;

pub use memory::LinuxProcessMemoryReader;
pub use process::ProcessView;
