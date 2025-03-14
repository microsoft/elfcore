// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! x86_64 specifics for ELF core dump files.

use super::ArchComponentState;
use crate::ptrace::ptrace_get_reg_set;
use crate::CoreError;
use nix::unistd::Pid;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

// amd64 machine
pub const EM_X86_64: u16 = 62;

// amd64 notes
pub const NT_X86_XSTATE: u32 = 0x202;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, IntoBytes, Immutable)]
pub struct elf_gregset_t {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

//const AT_SYSINFO_X86: u64 = 32;
//const AT_SYSINFO_EHDR_X86: u64 = 33; returns vdso

pub fn get_x86_xsave_set(pid: Pid) -> Result<Vec<u8>, CoreError> {
    ptrace_get_reg_set(pid, NT_X86_XSTATE)
}

pub fn get_arch_components(pid: Pid) -> Result<Vec<ArchComponentState>, CoreError> {
    let components = vec![ArchComponentState {
        name: "XSAVE",
        note_type: NT_X86_XSTATE,
        note_name: b"LINUX",
        data: get_x86_xsave_set(pid)?,
    }];

    Ok(components)
}

pub fn get_gpr_set(gpr_state: &[u64]) -> elf_gregset_t {
    elf_gregset_t {
        r15: gpr_state[0],
        r14: gpr_state[1],
        r13: gpr_state[2],
        r12: gpr_state[3],
        rbp: gpr_state[4],
        rbx: gpr_state[5],
        r11: gpr_state[6],
        r10: gpr_state[7],
        r9: gpr_state[8],
        r8: gpr_state[9],
        rax: gpr_state[10],
        rcx: gpr_state[11],
        rdx: gpr_state[12],
        rsi: gpr_state[13],
        rdi: gpr_state[14],
        orig_rax: gpr_state[15],
        rip: gpr_state[16],
        cs: gpr_state[17],
        eflags: gpr_state[18],
        rsp: gpr_state[19],
        ss: gpr_state[20],
        fs_base: gpr_state[21],
        gs_base: gpr_state[22],
        ds: gpr_state[23],
        es: gpr_state[24],
        fs: gpr_state[25],
        gs: gpr_state[26],
    }
}
