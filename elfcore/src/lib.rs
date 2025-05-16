// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A Rust library for creating ELF core dump files.

#![warn(missing_docs)]

mod arch;
mod coredump;
mod elf;
mod error;

#[cfg(target_os = "linux")]
mod linux;

pub use arch::ArchComponentState;
pub use arch::ArchState;
pub use coredump::CoreDumpBuilder;
pub use coredump::MappedFile;
pub use coredump::VaProtection;
pub use coredump::VaRegion;
pub use elf::Elf64_Auxv;
pub use error::CoreError;

// Linux specific functionality
#[cfg(target_os = "linux")]
pub use coredump::write_core_dump;
#[cfg(target_os = "linux")]
pub use linux::{LinuxProcessMemoryReader, ProcessView};

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
///    pid: i32,
///    threads: Vec<ThreadView>,
///    va_regions: Vec<VaRegion>,
///    page_size: usize,
/// }
///
/// impl ProcessInfoSource for CustomSource {
///   fn pid(&self) -> i32 {
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
///   pid: nix::unistd::getpid().as_raw(),
///   threads: vec![ThreadView {
///     flags: 0, // Kernel flags for the process
///     tid: nix::unistd::getpid().as_raw(),
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
/// let mut cdb = CoreDumpBuilder::from_source(custom_source, custom_reader);
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

/// Linux Light-weight Process
#[derive(Debug)]
pub struct ThreadView {
    /// Thread id.
    pub tid: i32,

    /// Command line.
    pub cmd_line: String,

    /// The filename of the executable, in parentheses.
    /// This is visible whether or not the executable is
    /// swapped out.
    pub comm: String,

    /// One of the following characters, indicating process
    /// state:
    ///          R  Running
    ///          S  Sleeping in an interruptible wait
    ///          D  Waiting in uninterruptible disk sleep
    ///          Z  Zombie
    ///          T  Stopped (on a signal) or (before Linux 2.6.33)
    ///             trace stopped
    ///          t  Tracing stop (Linux 2.6.33 onward)
    ///          W  Paging (only before Linux 2.6.0)
    ///          X  Dead (from Linux 2.6.0 onward)
    ///          x  Dead (Linux 2.6.33 to 3.13 only)
    ///          K  Wakekill (Linux 2.6.33 to 3.13 only)
    ///          W  Waking (Linux 2.6.33 to 3.13 only)
    ///          P  Parked (Linux 3.9 to 3.13 only)
    pub state: u8,

    /// The PID of the parent of this process.
    pub ppid: i32,

    /// The process group ID of the process.
    pub pgrp: i32,

    /// The session ID of the process.
    pub session: i32,

    /// The kernel flags word of the process.  For bit mean‐
    /// ings, see the PF_* defines in the Linux kernel
    /// source file include/linux/sched.h.  Details depend
    /// on the kernel version.
    /// The format for this field was %lu before Linux 2.6.
    pub flags: i32,

    /// Amount of time that this process has been scheduled
    /// in user mode, measured in clock ticks (divide by
    /// sysconf(_SC_CLK_TCK)).  This includes guest time,
    /// guest_time (time spent running a virtual CPU, see
    /// below), so that applications that are not aware of
    /// the guest time field do not lose that time from
    /// their calculations.
    pub utime: u64,

    /// Amount of time that this process has been scheduled
    /// in kernel mode, measured in clock ticks (divide by
    /// sysconf(_SC_CLK_TCK)).
    pub stime: u64,

    /// Amount of time that this process's waited-for chil‐
    /// dren have been scheduled in user mode, measured in
    /// clock ticks (divide by sysconf(_SC_CLK_TCK)).  (See
    /// also times(2).)  This includes guest time,
    /// cguest_time (time spent running a virtual CPU, see
    /// below).
    pub cutime: u64,

    /// Amount of time that this process's waited-for chil‐
    /// dren have been scheduled in kernel mode, measured in
    /// clock ticks (divide by sysconf(_SC_CLK_TCK)).
    pub cstime: u64,

    /// The nice value (see setpriority(2)), a value in the
    /// range 19 (low priority) to -20 (high priority).
    pub nice: u64,

    /// User Id.
    pub uid: u64,

    /// Group Id.
    pub gid: u32,

    /// Current signal.
    pub cursig: u16,

    /// Blocked signal.
    pub sighold: u64,

    /// Pending signal.
    pub sigpend: u64,

    /// State of the CPU
    pub arch_state: Box<arch::ArchState>,
}
