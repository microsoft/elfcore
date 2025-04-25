// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code for linux specific functionality
//!
//! Gathering process information.

use super::memory::{FastMemoryReader, SlowMemoryReader};
use super::ptrace::ptrace_interrupt;
use crate::arch::Arch;
use crate::coredump::{MappedFile, MappedFileRegion, VaProtection, VaRegion};
use crate::elf::{
    Elf64_Auxv, Elf64_Ehdr, EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3, EI_VERSION, ELFMAG0, ELFMAG1,
    ELFMAG2, ELFMAG3, ET_DYN, ET_EXEC, EV_CURRENT,
};
use crate::{arch, ProcessInfoSource, ReadProcessMemory};
use crate::{CoreError, ThreadView};
use nix::libc::Elf64_Phdr;
use nix::sys;
use nix::sys::ptrace::{seize, Options};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use nix::unistd::{sysconf, SysconfVar};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::{BufRead, IoSliceMut, Read};
use zerocopy::AsBytes;
use zerocopy::FromZeroes;

impl ThreadView {
    pub(crate) fn new(pid: Pid, tid: Pid) -> Result<Self, CoreError> {
        let cmd_line_path = format!("/proc/{}/task/{}/cmdline", pid, tid);
        tracing::debug!("Reading {cmd_line_path}");
        let cmd_line = fs::read_to_string(cmd_line_path)?;

        // When parsing the stat file, have to handle the spaces in the program path.
        //
        // Here is the RE for the line:
        //
        // r"(\d+) \({1,1}?(.*)\){1,1}? ([RSDZTtWXxKWP]) "
        // r"([+-]?\d+) ([+-]?\d+) ([+-]?\d+) ([+-]?\d+) ([+-]?\d+) ([+-]?\d+) (\d+) (\d+) (\d+) "
        // r"(\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) "
        // r"(\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)"

        let stat_path = format!("/proc/{}/task/{}/stat", pid, tid);
        tracing::debug!("Reading {stat_path}");
        let stat_str = fs::read_to_string(stat_path)?;
        let stat_str_trim = stat_str.trim();

        let comm_pos_start = stat_str_trim.find('(');
        let comm_pos_end = stat_str_trim.rfind(')');
        if comm_pos_start.is_none() || comm_pos_end.is_none() {
            tracing::error!(
                "Unsupported format of the procfs stat file, could not find command line: {}",
                stat_str
            );
            return Err(CoreError::ProcParsingError);
        }
        let comm_pos_start = comm_pos_start.unwrap();
        let comm_pos_end = comm_pos_end.unwrap();
        let comm = String::from(&stat_str_trim[comm_pos_start + 1..comm_pos_end - 1]);

        let stat_str_split = stat_str_trim[comm_pos_end + 2..]
            .split(' ')
            .collect::<Vec<_>>();
        if stat_str_split.len() < 30 {
            tracing::error!("Unsupported format of the procfs stat file: {}, found {} entries after the command line", stat_str, stat_str_split.len());
            return Err(CoreError::ProcParsingError);
        }

        let state = {
            let mut buf = [0_u8; 8];
            stat_str_split[0]
                .chars()
                .next()
                .ok_or(CoreError::ProcParsingError)?
                .encode_utf8(&mut buf);

            buf[0]
        };

        let mut uid: u64 = 0;
        let mut gid: u32 = 0;
        let mut cursig: u16 = 0;
        let mut sighold: u64 = 0;
        let mut sigpend: u64 = 0;

        {
            let status_path = format!("/proc/{pid}/task/{tid}/status");
            tracing::debug!("Reading {status_path}");
            let status_file = fs::File::open(&status_path)?;
            let reader = std::io::BufReader::new(status_file);

            // The common trait for the lines is a prefix followed by the tab
            // character and then there is a number. After the number there might be
            // various characters (whitespace, slashes) so using splitn seems to be
            // difficult.

            let parse_first_number = |s: &str| {
                s.chars()
                    .map(|c| c.to_digit(10))
                    .take_while(|opt| opt.is_some())
                    .fold(0, |acc: u64, digit| acc * 10 + digit.unwrap() as u64)
            };

            for line in reader.lines() {
                let line = line?;
                let line = line.trim();

                tracing::debug!("Reading {status_path}: {line}");

                if let Some(s) = line.strip_prefix("Uid:\t") {
                    uid = parse_first_number(s);
                } else if let Some(s) = line.strip_prefix("Gid:\t") {
                    gid = parse_first_number(s) as u32;
                } else if let Some(s) = line.strip_prefix("SigQ:\t") {
                    cursig = parse_first_number(s) as u16;
                } else if let Some(s) = line.strip_prefix("SigBlk:\t") {
                    sighold = parse_first_number(s)
                } else if let Some(s) = line.strip_prefix("SigPnd:\t") {
                    sigpend = parse_first_number(s)
                }
            }
        }

        let arch_state = arch::ArchState::new(tid)?;

        Ok(Self {
            tid: tid.as_raw(),
            cmd_line,
            comm,
            state,
            ppid: stat_str_split[1].parse::<i32>()?,
            pgrp: stat_str_split[2].parse::<i32>()?,
            session: stat_str_split[3].parse::<i32>()?,
            flags: stat_str_split[6].parse::<i32>()?,
            utime: stat_str_split[11].parse::<u64>()?,
            stime: stat_str_split[12].parse::<u64>()?,
            cutime: stat_str_split[13].parse::<u64>()?,
            cstime: stat_str_split[14].parse::<u64>()?,
            nice: stat_str_split[16].parse::<u64>()?,
            uid,
            gid,
            cursig,
            sighold,
            sigpend,
            arch_state,
        })
    }
}

/// View of a Linux light-weight process
pub struct ProcessView {
    pub(crate) pid: Pid,
    pub(crate) threads: Vec<ThreadView>,
    pub(crate) va_regions: Vec<VaRegion>,
    pub(crate) mapped_files: Vec<MappedFile>,
    // Auxiliary vector types.
    // The kernel exposes some system configuration using it.
    pub(crate) aux_vector: Vec<Elf64_Auxv>,
    pub(crate) page_size: usize,
}

fn get_thread_ids(pid: Pid) -> Result<Vec<Pid>, CoreError> {
    let mut threads = Vec::new();
    let task_dir = format!("/proc/{}/task", pid);
    tracing::debug!("Reading {task_dir}");
    let paths = std::fs::read_dir(task_dir)?;

    tracing::debug!(
        "Enumerating threads(light-weight processes) for the process {}",
        pid
    );

    for entry in paths {
        let entry = entry?;
        let path = entry.path();

        let metadata = std::fs::metadata(&path)?;
        if metadata.is_dir() {
            let stem = path.file_stem();
            if let Some(stem) = stem {
                if stem != "." && stem != ".." {
                    let stem = stem.to_string_lossy();
                    let tid = Pid::from_raw(stem.parse::<u32>()? as nix::libc::pid_t);

                    tracing::debug!("Found thread {}", tid);

                    threads.push(tid)
                }
            }
        }
    }

    Ok(threads)
}

fn get_aux_vector(pid: Pid) -> Result<Vec<Elf64_Auxv>, CoreError> {
    let mut auxv: Vec<Elf64_Auxv> = Vec::new();

    let auxv_file_name = format!("/proc/{}/auxv", pid);
    tracing::debug!("Reading {auxv_file_name}");
    let mut file = File::open(auxv_file_name)?;

    loop {
        let mut aux = Elf64_Auxv {
            a_type: 0,
            a_val: 0,
        };

        match file.read_exact(aux.as_bytes_mut()) {
            Ok(_) => auxv.push(aux),
            Err(_) => break,
        }
    }

    Ok(auxv)
}

fn get_va_regions(pid: Pid) -> Result<(Vec<VaRegion>, Vec<MappedFile>, u64), CoreError> {
    let mut maps: Vec<VaRegion> = Vec::new();
    let mut vdso = 0_u64;

    let mut mapped_elfs: HashSet<String> = HashSet::new();
    let mut mapped_non_elfs: HashSet<String> = HashSet::new();
    let mut mapped_files: Vec<MappedFile> = Vec::new();

    let maps_path = format!("/proc/{}/maps", pid);
    tracing::debug!("Reading {maps_path}");
    let maps_file = fs::File::open(maps_path)?;
    let reader = std::io::BufReader::new(maps_file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        tracing::debug!("Memory maps: {:?}", parts);

        let begin_end: Vec<&str> = parts[0].split('-').collect();
        let begin = u64::from_str_radix(begin_end[0], 16)?;
        let end = u64::from_str_radix(begin_end[1], 16)?;
        let offset = u64::from_str_radix(parts[2], 16)?;

        let mapped_file_name = {
            let last = *parts.last().ok_or(CoreError::ProcParsingError)?;
            if last == "[vdso]" {
                vdso = begin;

                //None
                tracing::info!("Skipping VA range mapped to {}", last);
                continue;
            } else if last == "[vvar]" || last == "[vsyscall]" {
                //None
                tracing::info!("Skipping VA range mapped to {}", last);
                continue;
            } else if last.starts_with('/') {
                if last.starts_with("/dev/") {
                    // Reading device memory might have unintended side effects.
                    // Always skip.
                    tracing::info!("Skipping VA range mapped to device file {}", last);
                    continue;
                }

                Some(String::from(last))
            } else {
                None
            }
        };

        let is_private = parts[1].chars().nth(3).ok_or(CoreError::ProcParsingError)? == 'p';
        let is_shared = parts[1].chars().nth(3).ok_or(CoreError::ProcParsingError)? == 's';

        if !is_private && !is_shared {
            tracing::info!(
                "Skipping non-accessible VA range [0x{:x}; 0x{:x}]",
                begin,
                end
            );
            continue;
        }

        let protection = VaProtection {
            read: parts[1].starts_with('r'),
            write: parts[1].chars().nth(1).ok_or(CoreError::ProcParsingError)? == 'w',
            execute: parts[1].chars().nth(2).ok_or(CoreError::ProcParsingError)? == 'x',
            is_private,
        };

        if !protection.read && !protection.write && !protection.execute {
            tracing::info!(
                "Skipping non-accessible VA range [0x{:x}; 0x{:x}]",
                begin,
                end
            );
            continue;
        }

        // TODO also can skip over read-only regions and executable regions.
        // These can be loaded from shared objects available on the system.

        // Was that file seen before and is that an ELF one?
        if let Some(ref mapped_file_name) = mapped_file_name {
            if !mapped_elfs.contains(mapped_file_name)
                && !mapped_non_elfs.contains(mapped_file_name)
            {
                // First time for that file.
                // See if the mapped file is an ELF one, otherwise skip over it
                // as it might be quite huge and may contains secrets, filter out by default.
                // TODO: make optional.

                let maybe_elf_hdr: Option<Elf64_Ehdr> = {
                    let mut elf_hdr = Elf64_Ehdr::new_zeroed();
                    match process_vm_readv(
                        pid,
                        &mut [IoSliceMut::new(elf_hdr.as_bytes_mut())],
                        &[RemoteIoVec {
                            base: begin as usize,
                            len: std::mem::size_of::<Elf64_Ehdr>(),
                        }],
                    ) {
                        Ok(_) => Some(elf_hdr),
                        Err(_) => None,
                    }
                };

                if let Some(elf_hdr) = maybe_elf_hdr {
                    if elf_hdr.e_ident[EI_MAG0] == ELFMAG0
                        && elf_hdr.e_ident[EI_MAG1] == ELFMAG1
                        && elf_hdr.e_ident[EI_MAG2] == ELFMAG2
                        && elf_hdr.e_ident[EI_MAG3] == ELFMAG3
                        && elf_hdr.e_ident[EI_VERSION] == EV_CURRENT
                        && elf_hdr.e_ehsize == std::mem::size_of::<Elf64_Ehdr>() as u16
                        && (elf_hdr.e_type == ET_EXEC || elf_hdr.e_type == ET_DYN)
                        && elf_hdr.e_phentsize == std::mem::size_of::<Elf64_Phdr>() as u16
                        && elf_hdr.e_machine == arch::ArchState::EM_ELF_MACHINE
                    {
                        mapped_elfs.insert(mapped_file_name.clone());
                    } else {
                        mapped_non_elfs.insert(mapped_file_name.clone());
                    }
                }
            }

            if mapped_non_elfs.contains(mapped_file_name) {
                tracing::info!(
                    "Skipping VA range mapped to a non-ELF file {}",
                    mapped_file_name
                );
                continue;
            } else {
                tracing::info!(
                    "Adding VA range [0x{:x}; 0x{:x}] mapped to an ELF file {}",
                    begin,
                    end,
                    mapped_file_name
                );
            }
        }

        // Account for the mapped files regions, not concerning
        // VA protection.

        if let Some(mapped_file_name) = &mapped_file_name {
            if mapped_files.is_empty() {
                mapped_files.push(MappedFile {
                    name: mapped_file_name.clone(),
                    regions: vec![MappedFileRegion { begin, end, offset }],
                })
            } else {
                let last_file = mapped_files.last_mut().ok_or(CoreError::ProcParsingError)?;
                if last_file.name != *mapped_file_name {
                    mapped_files.push(MappedFile {
                        name: mapped_file_name.clone(),
                        regions: vec![MappedFileRegion { begin, end, offset }],
                    })
                } else {
                    let last_region = last_file
                        .regions
                        .last_mut()
                        .ok_or(CoreError::ProcParsingError)?;

                    if last_region.end != begin {
                        last_file
                            .regions
                            .push(MappedFileRegion { begin, end, offset })
                    } else {
                        last_region.end = end
                    }
                }
            }
        }

        // Going to save that VA region into the core dump file

        maps.push(VaRegion {
            begin,
            end,
            offset,
            protection,
            mapped_file_name,
        });
    }

    maps.sort_by_key(|x| x.begin);

    Ok((maps, mapped_files, vdso))
}

impl ProcessView {
    /// Creates new process view
    ///
    /// # Arguments
    /// * `pid` - process ID
    ///
    pub fn new(pid: libc::pid_t) -> Result<Self, CoreError> {
        let pid = Pid::from_raw(pid);

        let mut tids = get_thread_ids(pid)?;
        tids.sort();

        // Guard against calling for itself. Fail early as the seizing the threads
        // will fail with -EPERM later.
        if tids.binary_search(&nix::unistd::getpid()).is_ok() {
            return Err(CoreError::CantDumpItself);
        };

        tracing::info!("Attaching to {} threads of process {}", tids.len(), pid);

        for tid in &tids {
            tracing::debug!("Seizing thread {}", *tid);

            if let Err(e) = seize(*tid, Options::empty()) {
                tracing::error!("Seizing thread {} failed, error {}", *tid, e);
                return Err(CoreError::NixError(e));
            }

            tracing::debug!("Interrupting thread {}", *tid);

            ptrace_interrupt(*tid)?;

            tracing::debug!("Waiting for thread {} to stop", *tid);

            match waitpid(*tid, None) {
                Ok(s) => {
                    tracing::debug!("Thread {} stopped, status {:?}", *tid, s);
                }
                Err(e) => {
                    tracing::error!("Waiting for thread {} failed, error {}", *tid, e);
                    return Err(CoreError::NixError(e));
                }
            }
        }

        // There is a race here:
        //  1) us stopping threads,
        //  2) the process that might be creating new ones,
        //  3) the existing threads might exit.
        // See if the threads ids are still the same. Not bullet-proof as thread ids
        // might be re-used.
        {
            let mut tids_check = get_thread_ids(pid)?;
            tids_check.sort();

            if tids != tids_check {
                return Err(CoreError::RaceTryAgain);
            }
        }

        let threads = tids
            .iter()
            .map(|tid| ThreadView::new(pid, *tid))
            .collect::<Result<_, _>>()?;
        for thread in &threads {
            tracing::debug!("Thread state: {:x?}", thread);
        }

        let (va_regions, mapped_files, vdso) = get_va_regions(pid)?;

        tracing::debug!("VA regions {:x?}", va_regions);
        tracing::debug!("Mapped files {:x?}", mapped_files);
        tracing::debug!("vDSO from the proc maps {:x?}", vdso);

        let aux_vector = get_aux_vector(pid)?;

        tracing::debug!("Auxiliary vector {:x?}", aux_vector);

        let page_size = match sysconf(SysconfVar::PAGE_SIZE) {
            Ok(s) => match s {
                Some(s) => s as usize,
                None => 0x1000_usize,
            },
            Err(_) => 0x1000_usize,
        };

        Ok(Self {
            pid,
            threads,
            va_regions,
            mapped_files,
            aux_vector,
            page_size,
        })
    }

    /// Retrieves the memory reader for access to memory regions
    pub(crate) fn create_memory_reader(pid: Pid) -> Result<Box<dyn ReadProcessMemory>, CoreError> {
        let memory_reader = if process_vm_readv_works() {
            tracing::info!("Using the fast process memory read on this system");
            Box::new(FastMemoryReader::new(pid)?) as Box<dyn ReadProcessMemory>
        } else {
            tracing::info!("Using the slow process memory read on this system");
            Box::new(SlowMemoryReader::new(pid)?) as Box<dyn ReadProcessMemory>
        };

        Ok(memory_reader)
    }
}

impl ProcessInfoSource for ProcessView {
    fn pid(&self) -> i32 {
        self.pid.as_raw()
    }
    fn threads(&self) -> &[ThreadView] {
        &self.threads
    }
    fn va_regions(&self) -> &[VaRegion] {
        &self.va_regions
    }
    fn mapped_files(&self) -> Option<&[MappedFile]> {
        Some(&self.mapped_files)
    }
    fn aux_vector(&self) -> Option<&[Elf64_Auxv]> {
        Some(&self.aux_vector)
    }
    fn page_size(&self) -> usize {
        self.page_size
    }
}

impl Drop for ProcessView {
    fn drop(&mut self) {
        tracing::info!(
            "Detaching from {} threads of process {}",
            self.threads.len(),
            self.pid
        );

        for thread in &self.threads {
            match sys::ptrace::detach(Pid::from_raw(thread.tid), None) {
                Ok(_) => {
                    tracing::debug!("Thread {} resumed", thread.tid);
                }
                Err(e) => {
                    tracing::error!("Thread {} failed to resume: {:?}", thread.tid, e);
                }
            };
        }
    }
}

/// The `process_vm_readv` system call might be unavailable. An extra check is made to be
/// sure the ABI works.
pub(crate) fn process_vm_readv_works() -> bool {
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
