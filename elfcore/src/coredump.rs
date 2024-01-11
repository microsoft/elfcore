// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code for collecting system information, thread status information, and saving core dump files.
//!
//! Panics must be avoided as that may leave the target process in a bad state
//! The code below must not do backward seeks so that the content can be streamed.

use super::arch;
use super::arch::Arch;
use crate::elf::*;
use crate::ptrace::ptrace_interrupt;
use crate::CoreError;
use nix::libc::Elf64_Phdr;
use nix::sys;
use nix::sys::ptrace::seize;
use nix::sys::ptrace::Options;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::RemoteIoVec;
use nix::sys::wait::waitpid;
use nix::unistd::sysconf;
use nix::unistd::Pid;
use nix::unistd::SysconfVar;
use smallvec::smallvec;
use smallvec::SmallVec;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::slice;
use zerocopy::AsBytes;
use zerocopy::FromZeroes;

const ELF_HEADER_ALIGN: usize = 8;
const NOTE_HEADER_PADDING: usize = 8;
const ELF_NOTE_PADDING: usize = 4;

/// Wraps a Write to emulate forward seeks
struct ElfCoreWriter<T: Write> {
    writer: T,
    written: usize,
}

impl<T> std::io::Write for ElfCoreWriter<T>
where
    T: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result = self.writer.write(buf);
        if let Ok(written) = result {
            self.written += written;
        }
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl<T> ElfCoreWriter<T>
where
    T: Write,
{
    pub fn new(writer: T) -> Self {
        Self { writer, written: 0 }
    }

    pub fn align_position(&mut self, alignment: u64) -> std::io::Result<usize> {
        const INLINE_CAPACITY: usize = 0x10000;

        let buf: SmallVec<[u8; INLINE_CAPACITY]> =
            smallvec![0; round_up(self.written as u64, alignment) as usize - self.written];
        self.write_all(&buf)?;
        Ok(buf.len())
    }

    pub fn stream_position(&self) -> std::io::Result<usize> {
        Ok(self.written)
    }
}

#[derive(AsBytes)]
#[repr(C, packed)]
struct MappedFilesNoteIntro {
    file_count: u64,
    page_size: u64,
}

#[derive(AsBytes)]
#[repr(C, packed)]
struct MappedFilesNoteItem {
    start_addr: u64,
    end_addr: u64,
    page_count: u64,
}

// Linux Light-weight Process
#[derive(Debug)]
struct ThreadView {
    // Thread id.
    tid: Pid,

    // Command line.
    cmd_line: String,

    // The filename of the executable, in parentheses.
    // This is visible whether or not the executable is
    // swapped out.
    comm: String,

    // One of the following characters, indicating process
    // state:
    //          R  Running
    //          S  Sleeping in an interruptible wait
    //          D  Waiting in uninterruptible disk sleep
    //          Z  Zombie
    //          T  Stopped (on a signal) or (before Linux 2.6.33)
    //             trace stopped
    //          t  Tracing stop (Linux 2.6.33 onward)
    //          W  Paging (only before Linux 2.6.0)
    //          X  Dead (from Linux 2.6.0 onward)
    //          x  Dead (Linux 2.6.33 to 3.13 only)
    //          K  Wakekill (Linux 2.6.33 to 3.13 only)
    //          W  Waking (Linux 2.6.33 to 3.13 only)
    //          P  Parked (Linux 3.9 to 3.13 only)
    state: u8,

    // The PID of the parent of this process.
    ppid: i32,

    // The process group ID of the process.
    pgrp: i32,

    // The session ID of the process.
    session: i32,

    // The kernel flags word of the process.  For bit mean‐
    // ings, see the PF_* defines in the Linux kernel
    // source file include/linux/sched.h.  Details depend
    // on the kernel version.
    // The format for this field was %lu before Linux 2.6.
    flags: i32,

    // Amount of time that this process has been scheduled
    // in user mode, measured in clock ticks (divide by
    // sysconf(_SC_CLK_TCK)).  This includes guest time,
    // guest_time (time spent running a virtual CPU, see
    // below), so that applications that are not aware of
    // the guest time field do not lose that time from
    // their calculations.
    utime: u64,

    // Amount of time that this process has been scheduled
    // in kernel mode, measured in clock ticks (divide by
    // sysconf(_SC_CLK_TCK)).
    stime: u64,

    // Amount of time that this process's waited-for chil‐
    // dren have been scheduled in user mode, measured in
    // clock ticks (divide by sysconf(_SC_CLK_TCK)).  (See
    // also times(2).)  This includes guest time,
    // cguest_time (time spent running a virtual CPU, see
    // below).
    cutime: u64,

    // Amount of time that this process's waited-for chil‐
    // dren have been scheduled in kernel mode, measured in
    // clock ticks (divide by sysconf(_SC_CLK_TCK)).
    cstime: u64,

    // The nice value (see setpriority(2)), a value in the
    // range 19 (low priority) to -20 (high priority).
    nice: u64,

    // User Id.
    uid: u64,

    // Group Id.
    gid: u32,

    // Current signal.
    cursig: u16,

    // Blocked signal.
    sighold: u64,

    // Pending signal.
    sigpend: u64,

    arch_state: Box<arch::ArchState>,
}

impl ThreadView {
    fn new(pid: Pid, tid: Pid) -> Result<Self, CoreError> {
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
            tid,
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

#[derive(Debug)]
#[allow(dead_code)]
struct VaProtection {
    is_private: bool,
    read: bool,
    write: bool,
    execute: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
struct VaRegion {
    begin: u64,
    end: u64,
    offset: u64,
    protection: VaProtection,
    mapped_file_name: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct MappedFileRegion {
    begin: u64,
    end: u64,
    offset: u64,
}

#[derive(Debug)]
struct MappedFile {
    name: String,
    regions: Vec<MappedFileRegion>,
}

#[derive(Default)]
struct NoteSizes {
    process_info: usize,
    process_status: usize,
    aux_vector: usize,
    mapped_files: usize,
    custom: usize,
    total_note_size: usize,
}

/// View of a Linux light-weight process
pub struct ProcessView {
    pid: Pid,
    threads: Vec<ThreadView>,
    va_regions: Vec<VaRegion>,
    mapped_files: Vec<MappedFile>,
    // Auxiliary vector types.
    // The kernel exposes some system configuration using it.
    aux_vector: Vec<Elf64_Auxv>,
    page_size: usize,
    custom_notes: Vec<(String, Vec<u8>)>,
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

fn get_elf_notes_sizes(pv: &ProcessView) -> Result<NoteSizes, CoreError> {
    let header_and_name = std::mem::size_of::<Elf64_Nhdr>() + NOTE_HEADER_PADDING;
    let process_info = header_and_name
        + round_up(
            std::mem::size_of::<prpsinfo_t>() as u64,
            ELF_NOTE_PADDING as u64,
        ) as usize;
    let one_thread_status = header_and_name
        + round_up(
            std::mem::size_of::<siginfo_t>() as u64,
            ELF_NOTE_PADDING as u64,
        ) as usize
        + header_and_name
        + round_up(
            (std::mem::size_of::<prstatus_t>() + {
                let mut arch_size = 0;
                for component in pv
                    .threads
                    .first()
                    .ok_or(CoreError::ProcParsingError)?
                    .arch_state
                    .components()
                {
                    arch_size += header_and_name + component.data.len();
                }
                arch_size
            }) as u64,
            ELF_NOTE_PADDING as u64,
        ) as usize;
    let process_status = one_thread_status * pv.threads.len();
    let aux_vector = header_and_name + pv.aux_vector.len() * std::mem::size_of::<Elf64_Auxv>();

    let mapped_files = {
        let mut addr_layout_size = 0_usize;
        let mut string_size = 0_usize;

        for mapped_file in &pv.mapped_files {
            string_size += (mapped_file.name.len() + 1) * mapped_file.regions.len();
            addr_layout_size +=
                std::mem::size_of::<MappedFilesNoteItem>() * mapped_file.regions.len();
        }

        let intro_size = std::mem::size_of::<MappedFilesNoteIntro>();

        header_and_name
            + round_up(
                (intro_size + addr_layout_size + string_size) as u64,
                ELF_NOTE_PADDING as u64,
            ) as usize
    };

    let custom: usize = pv.custom_notes.iter().map(|(_, data)| header_and_name + data.len()).sum();
    let custom = round_up(
        custom as u64,
        ELF_NOTE_PADDING as u64,
    ) as usize;

    let total_note_size = process_info + process_status + aux_vector + mapped_files + custom;

    tracing::info!("Estimated process info note size: {}", process_info);
    tracing::info!("Estimated process status note size: {}", process_status);
    tracing::info!("Estimated aux vector note size: {}", aux_vector);
    tracing::info!("Estimated mapped files note size: {}", mapped_files);
    tracing::info!("Estimated custom note size: {}", custom);
    tracing::info!("Estimated total note size: {}", total_note_size);

    Ok(NoteSizes {
        process_info,
        process_status,
        aux_vector,
        mapped_files,
        custom,
        total_note_size,
    })
}

impl ProcessView {
    /// Creates new process view
    ///
    /// # Arguments
    /// * `pid` - process ID
    ///
    pub fn new(pid: libc::pid_t) -> Result<Self, CoreError> {
        let pid = nix::unistd::Pid::from_raw(pid);

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
            custom_notes: Vec::new(),
        })
    }

    /// Add arbitrary additional data to the core dump as a note
    pub fn add_note(&mut self, data: Vec<u8>, name: &str) {
        self.custom_notes.push((name.to_owned(), data));
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
            match sys::ptrace::detach(thread.tid, None) {
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

/// Trait for those able to read the process virtual memory.
trait ReadProcessMemory {
    /// Read process memory into `buf` starting at the virtual address `base`,
    /// and returns the number of bytes and or the error.
    fn read_process_memory(&mut self, base: usize, buf: &mut [u8]) -> Result<usize, CoreError>;
}

/// A fast process memory reader employing the `process_vm_readv` system call
/// available on Linux 3.2+. It might be disabled on some systems in the kernel configuration.
struct FastMemoryReader {
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
struct SlowMemoryReader {
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

/// Writes an ELF core dump file
///
/// # Agruments:
/// * `writer` - a `std::io::Write` the data is sent to.
/// * `pv` - a `ProcessView` reference.
///
pub fn write_core_dump<T: Write>(writer: T, pv: &ProcessView) -> Result<usize, CoreError> {
    let mut total_written = 0_usize;
    let mut writer = ElfCoreWriter::new(writer);

    tracing::info!(
        "Creating core dump file for process {}. This process id: {}, this thread id: {}",
        pv.pid,
        nix::unistd::getpid(),
        nix::unistd::gettid()
    );

    let memory_reader = if process_vm_readv_works() {
        tracing::info!("Using the fast process memory read on this system");
        Box::new(FastMemoryReader::new(pv.pid)?) as Box<dyn ReadProcessMemory>
    } else {
        tracing::info!("Using the slow process memory read on this system");
        Box::new(SlowMemoryReader::new(pv.pid)?) as Box<dyn ReadProcessMemory>
    };

    let note_sizes = get_elf_notes_sizes(pv)?;

    total_written += write_elf_header(&mut writer, pv)?;
    total_written += writer.align_position(ELF_HEADER_ALIGN as u64)?;
    total_written += write_program_headers(&mut writer, pv, &note_sizes)?;
    total_written += writer.align_position(ELF_HEADER_ALIGN as u64)?;
    total_written += write_elf_notes(&mut writer, pv, &note_sizes)?;
    total_written += writer.align_position(pv.page_size as u64)?;
    total_written += write_va_regions(&mut writer, pv, memory_reader)?;

    tracing::info!("Wrote {} bytes for ELF core dump", total_written);

    Ok(total_written)
}

fn round_up(value: u64, alignment: u64) -> u64 {
    // Might be optimized if alignmet is a power of 2

    if value == 0 {
        return 0;
    }

    if value % alignment != 0 {
        (value + alignment) / alignment * alignment
    } else {
        value
    }
}

fn write_elf_header<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
) -> Result<usize, CoreError> {
    let mut e_ident = [0_u8; 16];
    e_ident[EI_MAG0] = ELFMAG0;
    e_ident[EI_MAG1] = ELFMAG1;
    e_ident[EI_MAG2] = ELFMAG2;
    e_ident[EI_MAG3] = ELFMAG3;
    e_ident[EI_CLASS] = ELFCLASS64;
    e_ident[EI_DATA] = ELFDATA2LSB; // TODO Assuming Little-Endian
    e_ident[EI_VERSION] = EV_CURRENT;
    e_ident[EI_OSABI] = ELFOSABI_NONE;

    let elf_header = Elf64_Ehdr {
        e_ident,
        e_type: ET_CORE,
        e_machine: arch::ArchState::EM_ELF_MACHINE,
        e_version: EV_CURRENT as u32,
        e_phoff: std::mem::size_of::<Elf64_Ehdr>() as u64,
        e_ehsize: std::mem::size_of::<Elf64_Ehdr>() as u16,
        e_phentsize: std::mem::size_of::<Elf64_Phdr>() as u16,
        e_phnum: 1 + pv.va_regions.len() as u16, // PT_NOTE and VA regions
        e_shentsize: 0,
        e_entry: 0,
        e_shoff: 0,
        e_flags: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    tracing::info!(
        "Writing ELF header at offset {}...",
        writer.stream_position()?
    );

    // SAFETY: Elf64_Ehdr is repr(C) with no padding bytes,
    // so all byte patterns are valid.
    let slice = unsafe {
        slice::from_raw_parts(
            &elf_header as *const _ as *mut u8,
            std::mem::size_of::<Elf64_Ehdr>(),
        )
    };
    writer.write_all(slice)?;

    tracing::info!("Wrote {} bytes", slice.len());

    Ok(slice.len())
}

fn write_program_headers<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
    note_sizes: &NoteSizes,
) -> Result<usize, CoreError> {
    tracing::info!(
        "Writing program headers at offset {}...",
        writer.stream_position()?
    );

    let mut written = 0_usize;

    // There will a header for PT_NOTE, and
    // as many PT_LOAD as there are VA regions.
    // Notes are situated right after the headers.

    let phdr_size = std::mem::size_of::<Elf64_Phdr>() * (pv.va_regions.len() + 1);
    let ehdr_size = std::mem::size_of::<Elf64_Ehdr>();
    let data_offset = round_up(ehdr_size as u64, ELF_HEADER_ALIGN as u64)
        + round_up(phdr_size as u64, ELF_HEADER_ALIGN as u64);

    {
        let mut note_header = Elf64_Phdr {
            p_type: PT_NOTE,
            p_flags: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: note_sizes.total_note_size as u64,
            p_memsz: note_sizes.total_note_size as u64,
            p_align: 1,
            p_offset: data_offset, // Notes are written after the headers
        };

        // SAFETY: Elf64_Phdr is repr(C) with no padding bytes,
        // so all byte patterns are valid.
        let slice = unsafe {
            slice::from_raw_parts_mut(
                &mut note_header as *mut _ as *mut u8,
                std::mem::size_of::<Elf64_Phdr>(),
            )
        };
        writer.write_all(slice)?;
        written += slice.len();
    }

    let mut current_offset = round_up(
        data_offset + note_sizes.total_note_size as u64,
        pv.page_size as u64,
    );

    for region in &pv.va_regions {
        let mut seg_header = Elf64_Phdr {
            p_type: PT_LOAD,
            p_flags: {
                const PF_X: u32 = 1u32 << 0;
                const PF_W: u32 = 1u32 << 1;
                const PF_R: u32 = 1u32 << 2;

                let mut seg_prot: u32 = 0;
                if region.protection.execute {
                    seg_prot |= PF_X;
                }
                if region.protection.write {
                    seg_prot |= PF_W;
                }
                if region.protection.read {
                    seg_prot |= PF_R;
                }

                seg_prot
            },
            p_offset: current_offset,
            p_vaddr: region.begin,
            p_paddr: 0,
            p_filesz: region.end - region.begin,
            p_memsz: region.end - region.begin,
            p_align: pv.page_size as u64,
        };

        // SAFETY: Elf64_Phdr is repr(C) with no padding bytes,
        // so all byte patterns are valid.
        let slice = unsafe {
            slice::from_raw_parts_mut(
                &mut seg_header as *mut _ as *mut u8,
                std::mem::size_of::<Elf64_Phdr>(),
            )
        };
        writer.write_all(slice)?;
        written += slice.len();

        current_offset += seg_header.p_filesz;
    }

    tracing::info!("Wrote {} bytes", written);

    Ok(written)
}

fn write_elf_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    note_kind: u32,
    name_bytes: &[u8],
    data: &[u8],
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    let mut note_header = Elf64_Nhdr {
        ntype: note_kind,
        namesz: std::cmp::min(name_bytes.len() as u32, 7),
        descsz: data.len() as u32,
    };

    let mut note_name = [0_u8; 8];
    for i in 0..note_header.namesz {
        note_name[i as usize] = name_bytes[i as usize];
    }

    // Account for the terminating zero.
    // ELF-64 Object File Format, Version 1.5 claims that is not required
    // but readelf and gdb refuse to read it otherwise

    note_header.namesz += 1;

    tracing::debug!(
        "Writing note header at offset {}...",
        writer.stream_position()?
    );

    writer.write_all(note_header.as_bytes())?;
    written += note_header.as_bytes().len();

    tracing::debug!(
        "Writing note name at offset {}...",
        writer.stream_position()?
    );

    writer.write_all(&note_name)?;
    written += note_name.len();

    tracing::debug!(
        "Writing note payload {} bytes at offset {}...",
        data.len(),
        writer.stream_position()?
    );

    writer.write_all(data)?;
    written += data.len();
    written += writer.align_position(ELF_NOTE_PADDING as u64)?;

    Ok(written)
}

fn write_process_info_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    tracing::info!(
        "Writing process info note at offset {}...",
        writer.stream_position()?
    );

    // Threads and processes in Linux are LWP (Light-weight processes)
    // TODO That's O(N) at worst, does that hurt?

    for thread_view in &pv.threads {
        if thread_view.tid == pv.pid {
            let pr_info = prpsinfo_t {
                pr_state: thread_view.state,
                pr_sname: thread_view.state,
                pr_zomb: if thread_view.state == b'Z' { 1 } else { 0 },
                pr_nice: thread_view.nice as u8,
                pad0: 0,
                pr_flag: thread_view.flags as u64,
                pr_uid: thread_view.uid as u32,
                pr_gid: thread_view.gid,
                pr_pid: thread_view.tid.as_raw() as u32,
                pr_ppid: thread_view.ppid as u32,
                pr_pgrp: thread_view.pgrp as u32,
                pr_sid: thread_view.session as u32,
                pr_fname: {
                    let bytes = thread_view.comm.as_bytes();
                    let mut fname = [0_u8; 16];

                    for i in 0..fname.len() {
                        if i < bytes.len() {
                            fname[i] = bytes[i];
                        } else {
                            break;
                        }
                    }

                    fname
                },
                pr_psargs: {
                    let bytes = thread_view.cmd_line.as_bytes();
                    let mut args = [0_u8; 80];

                    for i in 0..args.len() {
                        if i < bytes.len() {
                            args[i] = bytes[i];
                        } else {
                            break;
                        }
                    }

                    args
                },
            };
            written = write_elf_note(writer, NT_PRPSINFO, b"CORE", pr_info.as_bytes())?;
            break;
        }
    }

    tracing::info!("Wrote {} bytes for the process info note", written);

    Ok(written)
}

fn write_process_status_notes<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
) -> Result<usize, CoreError> {
    let mut total_written = 0_usize;

    tracing::info!(
        "Writing thread status notes at offset {}...",
        writer.stream_position()?
    );

    for thread_view in &pv.threads {
        let status = prstatus_t {
            si_signo: thread_view.cursig as u32,
            si_code: 0,
            si_errno: 0,
            pr_cursig: thread_view.cursig,
            pad0: 0,
            pr_sigpend: thread_view.sigpend,
            pr_sighold: thread_view.sighold,
            pr_pid: thread_view.tid.as_raw() as u32,
            pr_ppid: thread_view.ppid as u32,
            pr_pgrp: thread_view.pgrp as u32,
            pr_sid: thread_view.session as u32,
            pr_utime: pr_timeval_t {
                tv_sec: thread_view.utime / 1000,
                tv_usec: (thread_view.utime % 1000) * 1000,
            },
            pr_stime: pr_timeval_t {
                tv_sec: thread_view.stime / 1000,
                tv_usec: (thread_view.stime % 1000) * 1000,
            },
            pr_cutime: pr_timeval_t {
                tv_sec: thread_view.cutime / 1000,
                tv_usec: (thread_view.cutime % 1000) * 1000,
            },
            pr_cstime: pr_timeval_t {
                tv_sec: thread_view.cstime / 1000,
                tv_usec: (thread_view.cstime % 1000) * 1000,
            },
            pr_reg: thread_view.arch_state.greg_set(),
            pr_fpvalid: 1,
            pad1: 0,
        };

        let signals = siginfo_t {
            si_signo: thread_view.cursig as u32,
            si_errno: 0,
            si_code: 0,
            pad0: 0,
            si_data: [0_u32; 28],
        };

        let mut written = write_elf_note(writer, NT_PRSTATUS, b"CORE", status.as_bytes())?;
        total_written += written;

        for arch_component in thread_view.arch_state.components() {
            written = write_elf_note(
                writer,
                arch_component.note_type,
                arch_component.note_name,
                arch_component.data.as_bytes(),
            )?;
            total_written += written;
        }

        written = write_elf_note(writer, NT_SIGINFO, b"CORE", signals.as_bytes())?;
        total_written += written;
    }

    tracing::info!(
        "Wrote {} bytes for the thread status notes, {} notes",
        total_written,
        pv.threads.len()
    );

    Ok(total_written)
}

fn write_aux_vector_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
) -> Result<usize, CoreError> {
    tracing::info!(
        "Writing auxiliary vector at offset {}...",
        writer.stream_position()?
    );

    let written = write_elf_note(writer, NT_AUXV, b"CORE", pv.aux_vector.as_bytes())?;

    tracing::info!("Wrote {} bytes for the auxiliary vector", written);

    Ok(written)
}

fn write_mapped_files_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
) -> Result<usize, CoreError> {
    tracing::debug!(
        "Writing mapped files note at offset {}...",
        writer.stream_position()?
    );

    let mut data: Vec<u8> = Vec::with_capacity(pv.page_size);

    let mut intro = MappedFilesNoteIntro {
        file_count: 0,
        page_size: 1,
    };

    for mapped_file in &pv.mapped_files {
        intro.file_count += mapped_file.regions.len() as u64;
    }

    data.extend_from_slice(intro.as_bytes());

    // TODO: Sort by virtual address? Ranges always appear sorted in proc/maps

    for mapped_file in &pv.mapped_files {
        for region in &mapped_file.regions {
            let item = MappedFilesNoteItem {
                start_addr: region.begin,
                end_addr: region.end,
                page_count: region.offset, // No scaling
            };
            data.extend_from_slice(item.as_bytes());
        }
    }

    for mapped_file in &pv.mapped_files {
        for _ in &mapped_file.regions {
            data.extend_from_slice(mapped_file.name.as_bytes());
            data.push(0_u8);
        }
    }

    let written = write_elf_note(writer, NT_FILE, b"CORE", data.as_bytes())?;

    tracing::debug!("Wrote {} bytes for mapped files note", written);

    Ok(written)
}

fn write_custom_notes<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
) -> Result<usize, CoreError> {

    let mut total_written = 0;

    for (name, data) in &pv.custom_notes {
        tracing::info!(
            "Writing custom note \"{}\" at offset {}...",
            name,
            writer.stream_position()?
        );

        let written = write_elf_note(writer, 0xffffffff, name.as_bytes(), data)?;

        tracing::info!("Wrote {} bytes for the custom note", written);
        total_written += written;
    }

    Ok(total_written)
}


fn write_elf_notes<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
    note_sizes: &NoteSizes,
) -> Result<usize, CoreError> {
    let mut total_written = 0_usize;
    let mut written;

    tracing::info!("Writing notes at offset {}...", writer.stream_position()?);

    if note_sizes.process_info != 0 {
        written = write_process_info_note(writer, pv)?;
        if written != note_sizes.process_info {
            return Err(CoreError::InternalError(
                "Mismatched process info note size",
            ));
        }
        total_written += written;
    }

    if note_sizes.process_status != 0 {
        written = write_process_status_notes(writer, pv)?;
        if written != note_sizes.process_status {
            return Err(CoreError::InternalError(
                "Mismatched process status note size",
            ));
        }
        total_written += written;
    }

    if note_sizes.aux_vector != 0 {
        written = write_aux_vector_note(writer, pv)?;
        if written != note_sizes.aux_vector {
            return Err(CoreError::InternalError("Mismatched aux vector note size"));
        }
        total_written += written;
    }

    if note_sizes.mapped_files != 0 {
        written = write_mapped_files_note(writer, pv)?;
        if written != note_sizes.mapped_files {
            return Err(CoreError::InternalError(
                "Mismatched mapped files note size",
            ));
        }
        total_written += written;
    }

    if note_sizes.custom != 0 {
        written = write_custom_notes(writer, pv)?;
        if written != note_sizes.custom {
            return Err(CoreError::InternalError(
                "Mismatched custom note size",
            ));
        }
        total_written += written;
    }

    tracing::info!("Wrote {} bytes for notes", total_written);

    Ok(total_written)
}

fn write_va_region<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    va_region: &VaRegion,
    pv: &ProcessView,
    memory_reader: &mut Box<dyn ReadProcessMemory>,
) -> Result<usize, CoreError> {
    // For optimal performance should be in [8KiB; 64KiB] range.
    // Selected 64 KiB as data on various hardware platforms shows
    // peak performance in this case.
    const BUFFER_SIZE: usize = 0x10000;

    let mut dumped = 0_usize;
    let mut address = va_region.begin;
    let mut buffer = [0_u8; BUFFER_SIZE];

    while address < va_region.end {
        let len = std::cmp::min((va_region.end - address) as usize, BUFFER_SIZE);
        match memory_reader.read_process_memory(address as usize, &mut buffer[..len]) {
            Ok(bytes_read) => {
                writer.write_all(&buffer[..bytes_read])?;

                address += bytes_read as u64;
                dumped += bytes_read;
            }
            Err(_) => {
                // Every precaution has been taken to read the accessible
                // memory only and still something has gone wrong. Nevertheless,
                // have to make forward progress to dump exactly as much memory
                // as the caller expects.
                //
                // Save dummy data up to the next page boundary.

                // Page size is a power of two on modern platforms.
                debug_assert!(
                    pv.page_size.is_power_of_two(),
                    "Page size is expected to be a power of two"
                );

                // Round up with bit twiddling as the page size is a power of two.
                let next_address = (pv.page_size + address as usize) & !(pv.page_size - 1);
                let next_address = std::cmp::min(next_address, va_region.end as usize);
                let dummy_data_size = next_address - address as usize;

                let dummy_data: SmallVec<[u8; BUFFER_SIZE]> = smallvec![0xf1_u8; dummy_data_size];

                writer.write_all(&dummy_data[..dummy_data_size])?;

                address = next_address as u64;
                dumped += dummy_data_size;
            }
        }
    }

    Ok(dumped)
}

fn write_va_regions<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &ProcessView,
    mut memory_reader: Box<dyn ReadProcessMemory>,
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    tracing::info!(
        "Writing memory content at offset {}...",
        writer.stream_position()?
    );

    for va_region in &pv.va_regions {
        let dumped = write_va_region(writer, va_region, pv, &mut memory_reader)?;

        written += dumped;

        tracing::debug!(
            "Saved {} bytes from region [0x{:x}; 0x{:x}] of size {}, current file offset {}",
            dumped,
            va_region.begin,
            va_region.end,
            va_region.end - va_region.begin,
            writer.stream_position()?
        );
    }

    tracing::info!("Wrote {} bytes for VA regions", written);

    Ok(written)
}
