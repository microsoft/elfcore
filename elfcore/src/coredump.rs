// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code for collecting system information, thread status information, and saving core dump files.
//!
//! Panics must be avoided as that may leave the target process in a bad state
//! The code below must not do backward seeks so that the content can be streamed.

use super::arch;
use super::arch::Arch;
use crate::elf::*;
use crate::CoreError;
use crate::ProcessInfoSource;
use crate::ProcessView;
use crate::ReadProcessMemory;
use nix::libc::Elf64_Phdr;
use smallvec::smallvec;
use smallvec::SmallVec;
use std::io::Read;
use std::io::Write;
use std::slice;
use zerocopy::AsBytes;

const ELF_HEADER_ALIGN: usize = 8;
const ELF_NOTE_ALIGN: usize = 4;

const NOTE_NAME_CORE: &[u8] = b"CORE";

// For optimal performance should be in [8KiB; 64KiB] range.
// Selected 64 KiB as data on various hardware platforms shows
// peak performance in this case.
const BUFFER_SIZE: usize = 0x10000;

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

    pub fn write_padding(&mut self, bytes: usize) -> std::io::Result<usize> {
        let buf: SmallVec<[u8; BUFFER_SIZE]> = smallvec![0; bytes];
        self.write_all(&buf)?;
        Ok(buf.len())
    }

    pub fn align_position(&mut self, alignment: usize) -> std::io::Result<usize> {
        self.write_padding(round_up(self.written, alignment) - self.written)
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

/// Struct that describes a region's access permissions
#[derive(Debug)]
pub struct VaProtection {
    /// Field that indicates this is a private region
    pub is_private: bool,
    /// Read permissions
    pub read: bool,
    /// Write permissions
    pub write: bool,
    /// Execute permissions
    pub execute: bool,
}

/// Struct that describes a memory region
#[derive(Debug)]
pub struct VaRegion {
    /// Virtual address start
    pub begin: u64,
    /// Virtual address end
    pub end: u64,
    /// Offset in memory where the region resides
    pub offset: u64,
    /// Access permissions
    pub protection: VaProtection,
    /// Mapped file name
    pub mapped_file_name: Option<String>,
}

/// Type that describes a mapped file region
#[derive(Debug)]
pub struct MappedFileRegion {
    /// Virtual address start
    pub begin: u64,
    /// Virtual address end
    pub end: u64,
    /// Offset in memory where the region resides
    pub offset: u64,
}

/// Type that describes a mapped file
#[derive(Debug)]
pub struct MappedFile {
    /// File name
    pub name: String,
    /// File regions
    pub regions: Vec<MappedFileRegion>,
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

/// Information about a custom note that will be created from a file
struct CustomFileNote<'a> {
    /// Name used in the ELF note header
    pub name: String,
    /// (nonblocking) file to read from
    pub file: &'a mut dyn Read,
    /// Fixed size of the note, including header, name, data, and size
    /// File contents will be padded or truncated to fit.
    pub note_len: usize,
}

fn get_elf_notes_sizes(
    pv: &dyn ProcessInfoSource,
    custom_notes: Option<&[CustomFileNote<'_>]>,
) -> Result<NoteSizes, CoreError> {
    let header_and_name =
        std::mem::size_of::<Elf64_Nhdr>() + round_up(NOTE_NAME_CORE.len() + 1, ELF_NOTE_ALIGN);
    let process_info =
        header_and_name + round_up(std::mem::size_of::<prpsinfo_t>(), ELF_NOTE_ALIGN);
    let one_thread_status = header_and_name
        + round_up(std::mem::size_of::<siginfo_t>(), ELF_NOTE_ALIGN)
        + header_and_name
        + round_up(
            std::mem::size_of::<prstatus_t>() + {
                let mut arch_size = 0;
                for component in pv
                    .threads()
                    .first()
                    .ok_or(CoreError::ProcParsingError)?
                    .arch_state
                    .components()
                {
                    arch_size += header_and_name + component.data.len();
                }
                arch_size
            },
            ELF_NOTE_ALIGN,
        );
    let process_status = one_thread_status * pv.threads().len();
    // Calculate auxv size - do not count if no auxv
    let aux_vector = pv
        .aux_vector()
        .map(|auxv| header_and_name + std::mem::size_of_val(auxv))
        .unwrap_or(0);

    // Calculate mapped files size - do not count if no mapped files
    let mapped_files = pv
        .mapped_files()
        .map(|files| {
            let mut addr_layout_size = 0_usize;
            let mut string_size = 0_usize;

            for mapped_file in files {
                string_size += (mapped_file.name.len() + 1) * mapped_file.regions.len();
                addr_layout_size +=
                    std::mem::size_of::<MappedFilesNoteItem>() * mapped_file.regions.len();
            }

            let intro_size = std::mem::size_of::<MappedFilesNoteIntro>();

            header_and_name + round_up(intro_size + addr_layout_size + string_size, ELF_NOTE_ALIGN)
        })
        .unwrap_or(0);

    let custom = if let Some(custom_notes) = custom_notes {
        round_up(
            custom_notes.iter().map(|x| x.note_len).sum::<usize>(),
            ELF_NOTE_ALIGN,
        )
    } else {
        0
    };

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

/// Writes an ELF core dump file
///
/// # Agruments:
/// * `writer` - a `std::io::Write` the data is sent to.
/// * `pv` - a `ProcessView` reference.
///
/// To access new functionality, use [`CoreDumpBuilder`]
pub fn write_core_dump<T: Write>(writer: T, pv: &ProcessView) -> Result<usize, CoreError> {
    let memory_reader = ProcessView::create_memory_reader(pv.pid)?;
    write_core_dump_inner(writer, pv, None, memory_reader)
}

fn write_core_dump_inner<T: Write>(
    writer: T,
    pv: &dyn ProcessInfoSource,
    custom_notes: Option<&mut [CustomFileNote<'_>]>,
    memory_reader: Box<dyn ReadProcessMemory>,
) -> Result<usize, CoreError> {
    let mut total_written = 0_usize;
    let mut writer = ElfCoreWriter::new(writer);

    // Check if the process is valid: has threads and va regions
    if pv.threads().is_empty() || pv.va_regions().is_empty() {
        return Err(CoreError::CustomSourceInfo);
    }

    tracing::info!(
        "Creating core dump file for process {}. This process id: {}, this thread id: {}",
        pv.pid(),
        nix::unistd::getpid(),
        nix::unistd::gettid()
    );

    let note_sizes = get_elf_notes_sizes(pv, custom_notes.as_deref())?;

    total_written += write_elf_header(&mut writer, pv)?;
    total_written += writer.align_position(ELF_HEADER_ALIGN)?;
    total_written += write_program_headers(&mut writer, pv, &note_sizes)?;
    total_written += writer.align_position(ELF_HEADER_ALIGN)?;
    total_written += write_elf_notes(&mut writer, pv, &note_sizes, custom_notes)?;
    total_written += writer.align_position(pv.page_size())?;
    total_written += write_va_regions(&mut writer, pv, memory_reader)?;

    tracing::info!("Wrote {} bytes for ELF core dump", total_written);

    Ok(total_written)
}

fn round_up(value: usize, alignment: usize) -> usize {
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
    pv: &dyn ProcessInfoSource,
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
        e_phnum: 1 + pv.va_regions().len() as u16, // PT_NOTE and VA regions
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
    pv: &dyn ProcessInfoSource,
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

    let phdr_size = std::mem::size_of::<Elf64_Phdr>() * (pv.va_regions().len() + 1);
    let ehdr_size = std::mem::size_of::<Elf64_Ehdr>();
    let data_offset = round_up(ehdr_size, ELF_HEADER_ALIGN) + round_up(phdr_size, ELF_HEADER_ALIGN);

    {
        let mut note_header = Elf64_Phdr {
            p_type: PT_NOTE,
            p_flags: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: note_sizes.total_note_size as u64,
            p_memsz: note_sizes.total_note_size as u64,
            p_align: 1,
            p_offset: data_offset as u64, // Notes are written after the headers
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

    let mut current_offset = round_up(data_offset + note_sizes.total_note_size, pv.page_size());

    for region in pv.va_regions() {
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
            p_offset: current_offset as u64,
            p_vaddr: region.begin,
            p_paddr: 0,
            p_filesz: region.end - region.begin,
            p_memsz: region.end - region.begin,
            p_align: pv.page_size() as u64,
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

        current_offset += seg_header.p_filesz as usize;
    }

    tracing::info!("Wrote {} bytes", written);

    Ok(written)
}

fn write_elf_note_header<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    note_kind: u32,
    name_bytes: &[u8],
    data_len: usize,
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    // namesz accounts for the terminating zero.
    // ELF-64 Object File Format, Version 1.5 claims that is not required
    // but readelf and gdb refuse to read it otherwise

    let namesz = name_bytes.len() + 1;
    let note_header = Elf64_Nhdr {
        ntype: note_kind,
        namesz: namesz as u32,
        descsz: data_len as u32,
    };

    tracing::debug!(
        "Writing note header at offset {}...",
        writer.stream_position()?
    );
    writer.write_all(note_header.as_bytes())?;
    written += std::mem::size_of::<Elf64_Nhdr>();

    tracing::debug!(
        "Writing note name at offset {}...",
        writer.stream_position()?
    );

    writer.write_all(name_bytes)?;
    written += name_bytes.len();

    let padding = [0_u8; ELF_NOTE_ALIGN];
    let padding_len = round_up(namesz, ELF_NOTE_ALIGN) - namesz + 1;
    writer.write_all(&padding[..padding_len])?;
    written += padding_len;

    Ok(written)
}

fn write_elf_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    note_kind: u32,
    name_bytes: &[u8],
    data: &[u8],
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    written += write_elf_note_header(writer, note_kind, name_bytes, data.len())?;

    tracing::debug!(
        "Writing note payload {} bytes at offset {}...",
        data.len(),
        writer.stream_position()?
    );

    writer.write_all(data)?;
    written += data.len();
    written += writer.align_position(ELF_NOTE_ALIGN)?;

    Ok(written)
}

fn write_elf_note_file<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    note_kind: u32,
    name_bytes: &[u8],
    file: &mut dyn Read,
    note_len: usize,
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    let header_and_name =
        std::mem::size_of::<Elf64_Nhdr>() + round_up(name_bytes.len() + 1, ELF_NOTE_ALIGN);
    let data_len = note_len - header_and_name;
    written += write_elf_note_header(writer, note_kind, name_bytes, data_len)?;

    tracing::debug!(
        "Writing note payload {} bytes at offset {}...",
        data_len,
        writer.stream_position()?
    );

    let max_len = data_len - std::mem::size_of::<u32>();
    let total = std::io::copy(&mut file.take(max_len as u64), writer)? as usize;
    if file.read(&mut [0]).unwrap_or(0) != 0 {
        tracing::warn!(truncated_len = total, "note will be truncated");
    }
    written += total;

    if total < max_len {
        written += writer.write_padding(max_len - total)?;
    }

    writer.write_all((total as u32).as_bytes())?;
    written += std::mem::size_of::<u32>();
    written += writer.align_position(ELF_NOTE_ALIGN)?;

    Ok(written)
}

fn write_process_info_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &dyn ProcessInfoSource,
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    tracing::info!(
        "Writing process info note at offset {}...",
        writer.stream_position()?
    );

    // Threads and processes in Linux are LWP (Light-weight processes)
    // TODO That's O(N) at worst, does that hurt?

    for thread_view in pv.threads() {
        if thread_view.tid == pv.pid() {
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
            written = write_elf_note(writer, NT_PRPSINFO, NOTE_NAME_CORE, pr_info.as_bytes())?;
            break;
        }
    }

    tracing::info!("Wrote {} bytes for the process info note", written);

    Ok(written)
}

fn write_process_status_notes<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &dyn ProcessInfoSource,
) -> Result<usize, CoreError> {
    let mut total_written = 0_usize;

    tracing::info!(
        "Writing thread status notes at offset {}...",
        writer.stream_position()?
    );

    for thread_view in pv.threads() {
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

        let mut written = write_elf_note(writer, NT_PRSTATUS, NOTE_NAME_CORE, status.as_bytes())?;
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

        written = write_elf_note(writer, NT_SIGINFO, NOTE_NAME_CORE, signals.as_bytes())?;
        total_written += written;
    }

    tracing::info!(
        "Wrote {} bytes for the thread status notes, {} notes",
        total_written,
        pv.threads().len()
    );

    Ok(total_written)
}

fn write_aux_vector_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &dyn ProcessInfoSource,
) -> Result<usize, CoreError> {
    tracing::info!(
        "Writing auxiliary vector at offset {}...",
        writer.stream_position()?
    );

    let written = pv
        .aux_vector()
        .map(|auxv| write_elf_note(writer, NT_AUXV, NOTE_NAME_CORE, auxv.as_bytes()))
        .unwrap_or(Ok(0))?;

    tracing::info!("Wrote {} bytes for the auxiliary vector", written);

    Ok(written)
}

fn write_mapped_files_note<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &dyn ProcessInfoSource,
) -> Result<usize, CoreError> {
    tracing::info!(
        "Writing mapped files note at offset {}...",
        writer.stream_position()?
    );

    let written = pv
        .mapped_files()
        .map(|files| {
            let mut data: Vec<u8> = Vec::with_capacity(pv.page_size());

            let mut intro = MappedFilesNoteIntro {
                file_count: 0,
                page_size: 1,
            };

            for mapped_file in files {
                intro.file_count += mapped_file.regions.len() as u64;
            }

            data.extend_from_slice(intro.as_bytes());

            // TODO: Sort by virtual address? Ranges always appear sorted in proc/maps

            for mapped_file in files {
                for region in &mapped_file.regions {
                    let item = MappedFilesNoteItem {
                        start_addr: region.begin,
                        end_addr: region.end,
                        page_count: region.offset, // No scaling
                    };
                    data.extend_from_slice(item.as_bytes());
                }
            }

            for mapped_file in files {
                for _ in &mapped_file.regions {
                    data.extend_from_slice(mapped_file.name.as_bytes());
                    data.push(0_u8);
                }
            }

            write_elf_note(writer, NT_FILE, NOTE_NAME_CORE, data.as_bytes())
        })
        .unwrap_or(Ok(0))?;

    tracing::info!("Wrote {} bytes for mapped files note", written);

    Ok(written)
}

fn write_custom_notes<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    custom_notes: &mut [CustomFileNote<'_>],
) -> Result<usize, CoreError> {
    let mut total_written = 0;

    for note in custom_notes {
        tracing::info!(
            "Writing custom note \"{}\" at offset {}...",
            note.name,
            writer.stream_position()?
        );

        let written = write_elf_note_file(
            writer,
            0xffffffff,
            note.name.as_bytes(),
            &mut note.file,
            note.note_len,
        )?;

        tracing::info!("Wrote {} bytes for the custom note", written);
        total_written += written;
    }

    Ok(total_written)
}

fn write_elf_notes<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    pv: &dyn ProcessInfoSource,
    note_sizes: &NoteSizes,
    custom_notes: Option<&mut [CustomFileNote<'_>]>,
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

    if let Some(custom_notes) = custom_notes {
        written = write_custom_notes(writer, custom_notes)?;
        if written != note_sizes.custom {
            return Err(CoreError::InternalError("Mismatched custom note size"));
        }
        total_written += written;
    }

    tracing::info!("Wrote {} bytes for notes", total_written);

    Ok(total_written)
}

fn write_va_region<T: Write>(
    writer: &mut ElfCoreWriter<T>,
    va_region: &VaRegion,
    pv: &dyn ProcessInfoSource,
    memory_reader: &mut Box<dyn ReadProcessMemory>,
) -> Result<usize, CoreError> {
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
                    pv.page_size().is_power_of_two(),
                    "Page size is expected to be a power of two"
                );

                // Round up with bit twiddling as the page size is a power of two.
                let next_address = (pv.page_size() + address as usize) & !(pv.page_size() - 1);
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
    pv: &dyn ProcessInfoSource,
    mut memory_reader: Box<dyn ReadProcessMemory>,
) -> Result<usize, CoreError> {
    let mut written = 0_usize;

    tracing::info!(
        "Writing memory content at offset {}...",
        writer.stream_position()?
    );

    for va_region in pv.va_regions() {
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

/// A builder for generating a core dump of a process
/// optionally with custom notes with content from files
/// This also supports generating core dumps with information
/// from a custom source.
pub struct CoreDumpBuilder<'a> {
    pv: Box<dyn ProcessInfoSource>,
    custom_notes: Vec<CustomFileNote<'a>>,
    memory_reader: Box<dyn ReadProcessMemory>,
}

impl<'a> CoreDumpBuilder<'a> {
    /// Create a new core dump builder for the process with the provided PID
    pub fn new(pid: libc::pid_t) -> Result<Self, CoreError> {
        let pv = ProcessView::new(pid)?;
        let memory_reader = ProcessView::create_memory_reader(pv.pid)?;

        Ok(Self {
            pv: Box::new(pv) as Box<dyn ProcessInfoSource>,
            custom_notes: Vec::new(),
            memory_reader,
        })
    }

    /// Create a new core dump builder from a custom `ProcessInfoSource`
    pub fn from_source(
        source: Box<dyn ProcessInfoSource>,
        memory_reader: Box<dyn ReadProcessMemory>,
    ) -> CoreDumpBuilder<'a> {
        CoreDumpBuilder {
            pv: source,
            custom_notes: Vec::new(),
            memory_reader,
        }
    }

    /// Add the contents of a file as a custom note to the core dump
    pub fn add_custom_file_note(
        &mut self,
        name: &str,
        file: &'a mut dyn Read,
        note_len: usize,
    ) -> &mut Self {
        self.custom_notes.push(CustomFileNote {
            name: name.to_owned(),
            file,
            note_len,
        });
        self
    }

    /// Writes an ELF core dump file
    ///
    /// # Agruments:
    /// * `writer` - a `std::io::Write` the data is sent to.
    pub fn write<T: Write>(mut self, writer: T) -> Result<usize, CoreError> {
        write_core_dump_inner(
            writer,
            self.pv.as_ref(),
            Some(&mut self.custom_notes),
            self.memory_reader,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{ArchState, ThreadView};

    use super::*;

    struct MockProcessInfoSource {
        pid: nix::unistd::Pid,
        page_size: usize,
        regions: Vec<VaRegion>,
        threads: Vec<ThreadView>,
    }

    impl ProcessInfoSource for MockProcessInfoSource {
        fn pid(&self) -> nix::unistd::Pid {
            self.pid
        }

        fn page_size(&self) -> usize {
            self.page_size
        }

        fn threads(&self) -> &[ThreadView] {
            &self.threads
        }

        fn aux_vector(&self) -> Option<&[Elf64_Auxv]> {
            None
        }

        fn mapped_files(&self) -> Option<&[MappedFile]> {
            None
        }

        fn va_regions(&self) -> &[VaRegion] {
            &self.regions
        }
    }

    struct MockMemoryReader {}

    impl ReadProcessMemory for MockMemoryReader {
        fn read_process_memory(
            &mut self,
            _address: usize,
            buffer: &mut [u8],
        ) -> Result<usize, CoreError> {
            Ok(buffer.len())
        }
    }

    /// Test that writing a core dump using a custom source with no threads provided fails
    #[test]
    fn test_custom_source_no_threads() {
        let custom_source = Box::new(MockProcessInfoSource {
            pid: nix::unistd::getpid(),
            page_size: 4096,
            regions: vec![],
            threads: vec![],
        });

        let memory_reader = Box::new(MockMemoryReader {});

        let core_dump_builder = CoreDumpBuilder::from_source(custom_source, memory_reader);
        let res = core_dump_builder.write(std::io::sink());
        matches!(res, Err(CoreError::CustomSourceInfo));
    }

    /// Test that writing a core dump using a custom source with no regions provided fails
    #[test]
    fn test_custom_source_no_regions() {
        let custom_source = Box::new(MockProcessInfoSource {
            pid: nix::unistd::getpid(),
            page_size: 4096,
            regions: vec![],
            threads: vec![ThreadView {
                flags: 0, // Kernel flags for the process
                tid: nix::unistd::Pid::from_raw(0),
                uid: 0,               // User ID
                gid: 0,               // Group ID
                comm: "".to_string(), // Command name
                ppid: 0,              // Parent PID
                pgrp: 0,              // Process group ID
                nice: 0,              // Nice value
                state: 0,             // Process state
                utime: 0,             // User time
                stime: 0,             // System time
                cutime: 0,            // Children User time
                cstime: 0,            // Children User time
                cursig: 0,            // Current signal
                session: 0,           // Session ID of the process
                sighold: 0,           // Blocked signal
                sigpend: 0,           // Pending signal
                cmd_line: "".to_string(),

                arch_state: Box::new(ArchState {
                    gpr_state: vec![0; 27],
                    components: vec![],
                }),
            }],
        });

        let memory_reader = Box::new(MockMemoryReader {});

        let core_dump_builder = CoreDumpBuilder::from_source(custom_source, memory_reader);
        let res = core_dump_builder.write(std::io::sink());
        matches!(res, Err(CoreError::CustomSourceInfo));
    }

    /// Test that writing a core dump using a custom source with minimal info(threads, va regions,
    /// pid) succeeds
    #[test]
    fn test_custom_source_success() {
        let slice = [0_u8; 4096];
        // region that maps on the above slice
        let region = VaRegion {
            begin: 0x1000,
            end: 0x2000,
            offset: slice.as_ptr() as u64,
            mapped_file_name: None,
            protection: VaProtection {
                read: true,
                write: false,
                execute: false,
                is_private: false,
            },
        };
        let custom_source = Box::new(MockProcessInfoSource {
            pid: nix::unistd::getpid(),
            page_size: 4096,
            regions: vec![region],
            threads: vec![ThreadView {
                flags: 0, // Kernel flags for the process
                tid: nix::unistd::getpid(),
                uid: 0,               // User ID
                gid: 0,               // Group ID
                comm: "".to_string(), // Command name
                ppid: 0,              // Parent PID
                pgrp: 0,              // Process group ID
                nice: 0,              // Nice value
                state: 0,             // Process state
                utime: 0,             // User time
                stime: 0,             // System time
                cutime: 0,            // Children User time
                cstime: 0,            // Children User time
                cursig: 0,            // Current signal
                session: 0,           // Session ID of the process
                sighold: 0,           // Blocked signal
                sigpend: 0,           // Pending signal
                cmd_line: "".to_string(),

                arch_state: Box::new(ArchState {
                    gpr_state: vec![0; 27],
                    components: vec![],
                }),
            }],
        });

        let memory_reader = Box::new(MockMemoryReader {});

        let core_dump_builder = CoreDumpBuilder::from_source(custom_source, memory_reader);
        let res = core_dump_builder.write(std::io::sink());
        res.as_ref().unwrap();
        assert!(res.is_ok());
    }
}
