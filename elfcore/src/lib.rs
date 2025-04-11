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

pub use arch::ArchComponentState;
pub use arch::ArchState;
pub use coredump::write_core_dump;
pub use coredump::CoreDumpBuilder;
pub use coredump::MappedFile;
pub use coredump::VaProtection;
pub use coredump::VaRegion;
pub use elf::Elf64_Auxv;
pub use error::CoreError;
pub use linux::ProcessView;
pub use linux::ThreadView;
pub use nix::unistd::Pid;

/// Trait for those able to read the process virtual memory.
pub trait ReadProcessMemory {
    /// Read process memory into `buf` starting at the virtual address `base`,
    /// and returns the number of bytes and or the error.
    fn read_process_memory(&mut self, base: usize, buf: &mut [u8]) -> Result<usize, CoreError>;
}

/// This trait provides abstraction for the [`CoreDumpBuilder`] source information
///
/// By implementing this trait one can use the ELF output logic to create a core dump
/// file from any source of information.
/// This is useful for creating a core dump file from a process, that is not necessarily
/// linux process.
///
/// Example:
///
/// ```rust
/// use elfcore::ArchState;
/// use elfcore::CoreDumpBuilder;
/// use elfcore::CoreError;
/// use elfcore::Elf64_Auxv;
/// use elfcore::MappedFile;
/// use elfcore::ProcessInfoSource;
/// use elfcore::ReadProcessMemory;
/// use elfcore::ThreadView;
/// use elfcore::VaProtection;
/// use elfcore::VaRegion;
/// use std::fs::File;
///
/// struct CustomSource {
///    pid: nix::unistd::Pid,
///    threads: Vec<ThreadView>,
///    va_regions: Vec<VaRegion>,
///    page_size: usize,
/// }
///
/// impl ProcessInfoSource for CustomSource {
///   fn pid(&self) -> nix::unistd::Pid {
///     self.pid
///   }
///   fn threads(&self) -> &[ThreadView] {
///     &self.threads
///   }
///   fn va_regions(&self) -> &[VaRegion] {
///     &self.va_regions
///   }
///   fn mapped_files(&self) -> Option<&[MappedFile]> {
///     None
///   }
///   fn aux_vector(&self) -> Option<&[Elf64_Auxv]> {
///     None
///   }
///   fn page_size(&self) -> usize {
///     self.page_size
///   }
/// }
///
/// struct CustomReader {}
///
/// impl ReadProcessMemory for CustomReader {
///   fn read_process_memory(
///     &mut self,
///     base: usize,
///     buf: &mut [u8]) -> Result<usize, CoreError> {
///     // Implement logic to read memory from the process
///     Ok(buf.len())
///   }
/// }
///
/// // Example of process memory using a byte array
/// let process_memory = [0_u8; 4096];
///
/// // Example of ThreadView and VaRegion structures that can be used
/// // in the custom source
/// let custom_source = CustomSource {
///   pid: nix::unistd::getpid(),
///   threads: vec![ThreadView {
///     flags: 0, // Kernel flags for the process
///     tid: nix::unistd::getpid(),
///     uid: 0,               // User ID
///     gid: 0,               // Group ID
///     comm: "example".to_string(), // Command name
///     ppid: 0,              // Parent PID
///     pgrp: 0,              // Process group ID
///     nice: 0,              // Nice value
///     state: 0,             // Process state
///     utime: 0,             // User time
///     stime: 0,             // System time
///     cutime: 0,            // Children User time
///     cstime: 0,            // Children User time
///     cursig: 0,            // Current signal
///     session: 0,           // Session ID of the process
///     sighold: 0,           // Blocked signal
///     sigpend: 0,           // Pending signal
///     cmd_line: "example".to_string(),
///
///     arch_state: Box::new(ArchState {
///         gpr_state: vec![0; 27],
///         components: vec![],
///     }),
///   }],
///   va_regions: vec![VaRegion {
///     begin: 0x1000,
///     end: 0x2000,
///     offset: process_memory.as_ptr() as u64,
///     mapped_file_name: None,
///     protection: VaProtection {
///       read: true,
///       write: false,
///       execute: false,
///       is_private: false,
///     },
///   }],
///   page_size: 4096,
/// };
///
/// let custom_reader = CustomReader {};
///
/// // Create a core dump builder using the custom source and reader
/// let mut cdb = CoreDumpBuilder::from_source(Box::new(custom_source), Box::new(custom_reader));
///
/// // Writer used for example purposes only
/// let writer = std::io::sink();
/// let result = cdb.write(writer);
///
/// assert!(result.is_ok());
///
/// ```
pub trait ProcessInfoSource {
    /// Retrieves the PID of the process
    /// For a core dump file to be loaded on a linux platform, it must use the PID of the process running
    fn pid(&self) -> i32;
    /// Retrieves a slice of [`ThreadView`] structures that describe the running threads at the
    /// time of the core dump
    fn threads(&self) -> &[ThreadView];
    /// Retrieves a slice of [`VaRegion`] structures that describe the virtual address space of the
    /// process at the time of the core dump
    fn va_regions(&self) -> &[VaRegion];
    /// A slice of [`MappedFile`] structures that describe the mapped files at the time of the core
    /// dump
    fn mapped_files(&self) -> Option<&[MappedFile]>;
    /// Retrieves a slice of [`Elf64_Auxv`] structures that describe the auxiliary vector
    /// for the produced core dump
    fn aux_vector(&self) -> Option<&[Elf64_Auxv]>;
    /// Retrieves the page size that will be used for alignment of segments
    fn page_size(&self) -> usize;
}
