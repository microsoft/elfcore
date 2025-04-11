// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This submodule contains the `memory` handling functionality for the
//! a linux process.

use crate::CoreError;
use crate::ReadProcessMemory;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use std::io::{IoSliceMut, Read, Seek};

/// A fast process memory reader employing the `process_vm_readv` system call
/// available on Linux 3.2+. It might be disabled on some systems in the kernel configuration.
pub(crate) struct FastMemoryReader {
    pid: Pid,
}

impl FastMemoryReader {
    pub fn new(pid: Pid) -> Result<Self, CoreError> {
        Ok(Self { pid })
    }
}

impl ReadProcessMemory for FastMemoryReader {
    fn read_process_memory(&mut self, base: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        let len = buf.len();
        process_vm_readv(
            self.pid,
            &mut [IoSliceMut::new(buf)],
            &[RemoteIoVec { base, len }],
        )
        .map_err(CoreError::NixError)
    }
}

/// A slow but more compatible process memory reader, uses the `/proc/<pid>/mem`
/// file.
pub(crate) struct SlowMemoryReader {
    file: std::fs::File,
}

impl SlowMemoryReader {
    pub fn new(pid: Pid) -> Result<Self, CoreError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{pid}/mem"))
            .map_err(CoreError::IoError)?;
        Ok(Self { file })
    }
}

impl ReadProcessMemory for SlowMemoryReader {
    fn read_process_memory(&mut self, base: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        self.file
            .seek(std::io::SeekFrom::Start(base as u64))
            .map_err(CoreError::IoError)?;
        self.file.read_exact(buf).map_err(CoreError::IoError)?;

        Ok(buf.len())
    }
}
