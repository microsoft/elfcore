// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process trace helpers, not machine-specific ones.

use std::ffi::c_void;
use std::ptr;

use crate::elf::NT_PRFPREG;
use crate::elf::NT_PRSTATUS;
use crate::CoreError;
use nix::sys;
use nix::sys::ptrace::Request;
use nix::sys::ptrace::RequestType;
use nix::unistd::Pid;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

pub fn ptrace_get_reg_set<T: AsBytes + FromBytes>(pid: Pid, set: u32) -> Result<Vec<T>, CoreError> {
    let mut data = Vec::with_capacity(0x1000 / std::mem::size_of::<T>());
    let vec = nix::libc::iovec {
        iov_base: data.as_mut_ptr() as *mut c_void,
        iov_len: data.capacity() * std::mem::size_of::<T>(),
    };
    let err;

    // SAFETY: Using FFI with the process trace API to read raw bytes.
    unsafe {
        err = nix::libc::ptrace(
            Request::PTRACE_GETREGSET as RequestType,
            nix::libc::pid_t::from(pid),
            set,
            &vec as *const _ as *const c_void,
        );

        data.set_len(vec.iov_len / std::mem::size_of::<T>());
        data.shrink_to_fit();
    };

    nix::errno::Errno::result(err)?;
    Ok(data)
}

pub fn ptrace_interrupt(pid: Pid) -> Result<(), CoreError> {
    // SAFETY: Using FFI with the process trace API to read raw bytes.
    let ret = unsafe {
        nix::errno::Errno::clear();
        nix::libc::ptrace(
            nix::libc::PTRACE_INTERRUPT as sys::ptrace::RequestType,
            nix::libc::pid_t::from(pid),
            ptr::null_mut::<c_void>(),
            ptr::null_mut::<c_void>(),
        )
    };
    match nix::errno::Errno::result(ret) {
        Ok(..) => Ok(()),
        Err(e) => Err(CoreError::NixError(e)),
    }
}

pub fn get_gp_reg_set(pid: Pid) -> Result<Vec<u64>, CoreError> {
    ptrace_get_reg_set(pid, NT_PRSTATUS)
}

pub fn get_fp_reg_set(pid: Pid) -> Result<Vec<u8>, CoreError> {
    ptrace_get_reg_set(pid, NT_PRFPREG)
}
