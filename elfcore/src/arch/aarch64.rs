// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Aarch64 specifics for ELF core dump files.

use super::ArchComponentState;
use crate::ptrace::ptrace_get_reg_set;
use crate::CoreError;
use nix::unistd::Pid;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

// aarch64 machine
pub const EM_AARCH64: u16 = 183;

// aarch64 notes
pub const NT_ARM_TLS: u32 = 0x401;
pub const NT_ARM_HW_BREAK: u32 = 0x402;
pub const NT_ARM_HW_WATCH: u32 = 0x403;
pub const NT_ARM_SYSTEM_CALL: u32 = 0x404;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, IntoBytes, Immutable)]
pub struct elf_gregset_t {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

pub fn get_aarch64_tls(pid: Pid) -> Result<Vec<u8>, CoreError> {
    ptrace_get_reg_set(pid, NT_ARM_TLS)
}
pub fn get_aarch64_hw_break(pid: Pid) -> Result<Vec<u8>, CoreError> {
    ptrace_get_reg_set(pid, NT_ARM_HW_BREAK)
}
pub fn get_aarch64_hw_watch(pid: Pid) -> Result<Vec<u8>, CoreError> {
    ptrace_get_reg_set(pid, NT_ARM_HW_WATCH)
}
pub fn get_aarch64_system_call(pid: Pid) -> Result<Vec<u8>, CoreError> {
    ptrace_get_reg_set(pid, NT_ARM_SYSTEM_CALL)
}

pub fn get_arch_components(pid: Pid) -> Result<Vec<ArchComponentState>, CoreError> {
    let components = vec![
        ArchComponentState {
            name: "TLS",
            note_type: NT_ARM_TLS,
            note_name: b"LINUX",
            data: get_aarch64_tls(pid)?,
        },
        ArchComponentState {
            name: "HW BREAK",
            note_type: NT_ARM_HW_BREAK,
            note_name: b"LINUX",
            data: get_aarch64_hw_break(pid)?,
        },
        ArchComponentState {
            name: "HW WATCH",
            note_type: NT_ARM_HW_WATCH,
            note_name: b"LINUX",
            data: get_aarch64_hw_watch(pid)?,
        },
        ArchComponentState {
            name: "SYSCALL",
            note_type: NT_ARM_SYSTEM_CALL,
            note_name: b"LINUX",
            data: get_aarch64_system_call(pid)?,
        },
    ];

    Ok(components)
}

pub fn get_gpr_set(gpr_state: &[u64]) -> elf_gregset_t {
    elf_gregset_t {
        regs: [
            gpr_state[0],
            gpr_state[1],
            gpr_state[2],
            gpr_state[3],
            gpr_state[4],
            gpr_state[5],
            gpr_state[6],
            gpr_state[7],
            gpr_state[8],
            gpr_state[9],
            gpr_state[10],
            gpr_state[11],
            gpr_state[12],
            gpr_state[13],
            gpr_state[14],
            gpr_state[15],
            gpr_state[16],
            gpr_state[17],
            gpr_state[18],
            gpr_state[19],
            gpr_state[20],
            gpr_state[21],
            gpr_state[22],
            gpr_state[23],
            gpr_state[24],
            gpr_state[25],
            gpr_state[26],
            gpr_state[27],
            gpr_state[28],
            gpr_state[29],
            gpr_state[30],
        ],
        sp: gpr_state[31],
        pc: gpr_state[32],
        pstate: gpr_state[33],
    }
}
