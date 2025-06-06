// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ELF constants. There is the `object` crate that is pretty large.
//! Need a tiny portion of ELF specification as the code might run in a very
//! constrained environment.

use super::arch;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

pub const EI_MAG0: usize = 0;
pub const EI_MAG1: usize = 1;
pub const EI_MAG2: usize = 2;
pub const EI_MAG3: usize = 3;
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;

pub const ELFMAG0: u8 = 0x7f;
pub const ELFMAG1: u8 = b'E';
pub const ELFMAG2: u8 = b'L';
pub const ELFMAG3: u8 = b'F';

/// ELF version
pub const EV_CURRENT: u8 = 1;

/// Executable file
#[cfg(target_os = "linux")]
pub const ET_EXEC: u16 = 2;
/// Shared object file
#[cfg(target_os = "linux")]
pub const ET_DYN: u16 = 3;
/// Core file
pub const ET_CORE: u16 = 4;
/// ELF class
pub const ELFCLASS64: u8 = 2;
/// Endianness
pub const ELFDATA2LSB: u8 = 1;

/// No ELF ABI
pub const ELFOSABI_NONE: u8 = 0;
//const ELFOSABI_LINUX: u8 = 3;

/// Loadable program segment
pub const PT_LOAD: u32 = 1;
/// Auxiliary information
pub const PT_NOTE: u32 = 4;

// ELF note types

/// Program status note
pub const NT_PRSTATUS: u32 = 1;
/// Program floating point registers note
#[cfg(target_os = "linux")]
pub const NT_PRFPREG: u32 = 2;
/// Program information note
pub const NT_PRPSINFO: u32 = 3;
/// Auxiliary vector note
pub const NT_AUXV: u32 = 6;
/// Signal information note
pub const NT_SIGINFO: u32 = 0x53494749;
/// Mapped files note
pub const NT_FILE: u32 = 0x46494c45;

/// Program status
#[derive(AsBytes)]
#[repr(C)]
pub struct prpsinfo_t {
    // total size (bytes):  136
    pub pr_state: u8,
    pub pr_sname: u8,
    pub pr_zomb: u8,
    pub pr_nice: u8,
    pub pad0: u32,
    pub pr_flag: u64,
    pub pr_uid: u32,
    pub pr_gid: u32,
    pub pr_pid: u32,
    pub pr_ppid: u32,
    pub pr_pgrp: u32,
    pub pr_sid: u32,
    pub pr_fname: [u8; 16],
    pub pr_psargs: [u8; 80],
}

/// Signal information
#[derive(AsBytes)]
#[repr(C)]
pub struct siginfo_t {
    // total size (bytes):  128
    pub si_signo: u32,
    pub si_errno: u32,
    pub si_code: u32,
    pub pad0: u32,
    pub si_data: [u32; 28],
}

/// Kernel time value
#[derive(AsBytes)]
#[repr(C)]
pub struct pr_timeval_t {
    pub tv_sec: u64,
    pub tv_usec: u64,
}

/// Program status
#[derive(AsBytes)]
#[repr(C)]
pub struct prstatus_t {
    // total size (bytes):  336 (x86_64)
    pub si_signo: u32,
    pub si_code: u32,
    pub si_errno: u32,
    pub pr_cursig: u16,
    pub pad0: u16,
    pub pr_sigpend: u64,
    pub pr_sighold: u64,
    pub pr_pid: u32,
    pub pr_ppid: u32,
    pub pr_pgrp: u32,
    pub pr_sid: u32,
    pub pr_utime: pr_timeval_t,
    pub pr_stime: pr_timeval_t,
    pub pr_cutime: pr_timeval_t,
    pub pr_cstime: pr_timeval_t,
    pub pr_reg: arch::elf_gregset_t,
    pub pr_fpvalid: u32,
    pub pad1: u32,
}

/// ELF auxiliary vector note
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C)]
pub struct Elf64_Auxv {
    /// AUXV type
    pub a_type: u64, // from auxvec.h
    /// AUXV value
    pub a_val: u64,
}

/// ELF note header
#[derive(AsBytes)]
#[repr(C)]
pub struct Elf64_Nhdr {
    pub namesz: u32,
    pub descsz: u32,
    pub ntype: u32,
}

/// ELF header
#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct Elf64_Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF program header
#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct Elf64_Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}
