// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This submodule contains the `memory` handling functionality for the
//! a linux process.

use crate::CoreError;
use crate::ReadProcessMemory;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use std::io::{IoSliceMut, Read, Seek};

/// The memory reader for the process
/// This concrete type is used for easier generic trait implementation
/// in the `coredump` module.
pub enum LinuxProcessMemoryReader {
    /// A fast process memory reader employing the `process_vm_readv` system call
    /// available on Linux 3.2+. It might be disabled on some systems in the kernel configuration.
    Fast {
        /// The process ID of the target process
        pid: Pid,
    },
    /// A slow but more compatible process memory reader, uses the `/proc/<pid>/mem`
    /// file.
    Slow {
        /// The file handle to the `/proc/<pid>/mem` file
        file: std::fs::File,
    },
}

impl LinuxProcessMemoryReader {
    /// Create a new process memory reader for the given process ID.
    /// It will use the fast method if available, otherwise it will fall back to the slow method.
    pub fn new(pid: Pid) -> Result<Self, CoreError> {
        let memory_reader = if process_vm_readv_works() {
            Self::Fast { pid }
        } else {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .open(format!("/proc/{pid}/mem"))
                .map_err(CoreError::IoError)?;
            Self::Slow { file }
        };

        Ok(memory_reader)
    }
}

impl ReadProcessMemory for LinuxProcessMemoryReader {
    fn read_process_memory(&mut self, base: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        match self {
            Self::Fast { pid } => {
                let len = buf.len();
                process_vm_readv(
                    *pid,
                    &mut [IoSliceMut::new(buf)],
                    &[RemoteIoVec { base, len }],
                )
                .map_err(CoreError::NixError)
            }
            Self::Slow { file } => {
                file.seek(std::io::SeekFrom::Start(base as u64))
                    .map_err(CoreError::IoError)?;
                file.read_exact(buf).map_err(CoreError::IoError)?;

                Ok(buf.len())
            }
        }
    }
}

/// The `process_vm_readv` system call might be unavailable. An extra check is made to be
/// sure the ABI works.
fn process_vm_readv_works() -> bool {
    let probe_in = [0xc1c2c3c4c5c6c7c8_u64];
    let mut probe_out = 0u64.to_le_bytes();

    let result = process_vm_readv(
        nix::unistd::getpid(),
        &mut [IoSliceMut::new(&mut probe_out)],
        &[RemoteIoVec {
            base: probe_in.as_ptr() as usize,
            len: std::mem::size_of_val(&probe_in),
        }],
    );

    if let Err(e) = result {
        tracing::debug!("process_vm_readv has not succeeded, error {e:?}, won't be using it");
        return false;
    }

    if probe_in[0] != u64::from_le_bytes(probe_out) {
        tracing::debug!(
            "process_vm_readv did not return expected data: {probe_in:x?} != {probe_out:x?}, won't be using it"
        );
        return false;
    }

    true
}
