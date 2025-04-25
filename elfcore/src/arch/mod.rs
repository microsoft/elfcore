// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A Rust helper library with machine-specific code for ELF core dump files.

#[cfg(target_os = "linux")]
use {
    super::linux::ptrace,
    crate::{elf::NT_PRFPREG, CoreError},
    nix::unistd::Pid,
};

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::elf_gregset_t;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::elf_gregset_t;

/// Contains SSE registers on amd64, NEON on arm64,
/// XSAVE state on amd64, etc
#[derive(Debug)]
pub struct ArchComponentState {
    /// Name
    pub name: &'static str,
    /// Note type
    pub note_type: u32,
    /// Note name
    pub note_name: &'static [u8],
    /// Data
    pub data: Vec<u8>,
}

pub(crate) trait Arch {
    const EM_ELF_MACHINE: u16;

    #[cfg(target_os = "linux")]
    fn new(pid: Pid) -> Result<Box<Self>, CoreError>;
    #[allow(dead_code)]
    fn name() -> &'static str;
    fn greg_set(&self) -> elf_gregset_t;
    fn components(&self) -> &Vec<ArchComponentState>;
}

/// Describes CPU state
#[derive(Debug)]
pub struct ArchState {
    /// GP registers.
    pub gpr_state: Vec<u64>,

    /// Contains SSE registers on amd64, NEON on arm64,
    /// XSAVE state on amd64, etc
    pub components: Vec<ArchComponentState>,
}

impl Arch for ArchState {
    #[cfg(target_arch = "x86_64")]
    const EM_ELF_MACHINE: u16 = x86_64::EM_X86_64;
    #[cfg(target_arch = "aarch64")]
    const EM_ELF_MACHINE: u16 = aarch64::EM_AARCH64;

    #[cfg(target_os = "linux")]
    fn new(pid: Pid) -> Result<Box<Self>, CoreError> {
        tracing::debug!("Getting GP registers for #{pid}");
        let gpr_state = ptrace::get_gp_reg_set(pid)?;

        let mut components = vec![ArchComponentState {
            name: "Floating point",
            note_type: NT_PRFPREG,
            note_name: b"CORE",
            data: ptrace::get_fp_reg_set(pid)?,
        }];

        tracing::debug!("Getting extended register state for #{pid}");

        let ext_state = {
            #[cfg(target_arch = "x86_64")]
            {
                x86_64::get_arch_components(pid)
            }
            #[cfg(target_arch = "aarch64")]
            {
                aarch64::get_arch_components(pid)
            }
        };
        if let Ok(state) = ext_state {
            components.extend(state);
        } else {
            // XSAVE might be disabled, etc
            tracing::debug!("No extended register state for #{pid} is present");
        }

        Ok(Box::new(ArchState {
            gpr_state,
            components,
        }))
    }

    fn name() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "x86_64"
        }

        #[cfg(target_arch = "aarch64")]
        {
            "aarch64"
        }
    }

    fn greg_set(&self) -> elf_gregset_t {
        #[cfg(target_arch = "x86_64")]
        {
            x86_64::get_gpr_set(&self.gpr_state)
        }

        #[cfg(target_arch = "aarch64")]
        {
            aarch64::get_gpr_set(&self.gpr_state)
        }
    }

    fn components(&self) -> &Vec<ArchComponentState> {
        &self.components
    }
}
