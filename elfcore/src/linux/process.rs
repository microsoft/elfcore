// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code for linux specific functionality
//!
//! Gathering process information.

use crate::arch;
use crate::arch::Arch;
use crate::CoreError;
use nix::unistd::Pid;
use std::fs;
use std::io::BufRead;

// Linux Light-weight Process
#[derive(Debug)]
pub(crate) struct ThreadView {
    // Thread id.
    pub(crate) tid: Pid,

    // Command line.
    pub(crate) cmd_line: String,

    // The filename of the executable, in parentheses.
    // This is visible whether or not the executable is
    // swapped out.
    pub(crate) comm: String,

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
    pub(crate) state: u8,

    // The PID of the parent of this process.
    pub(crate) ppid: i32,

    // The process group ID of the process.
    pub(crate) pgrp: i32,

    // The session ID of the process.
    pub(crate) session: i32,

    // The kernel flags word of the process.  For bit mean‐
    // ings, see the PF_* defines in the Linux kernel
    // source file include/linux/sched.h.  Details depend
    // on the kernel version.
    // The format for this field was %lu before Linux 2.6.
    pub(crate) flags: i32,

    // Amount of time that this process has been scheduled
    // in user mode, measured in clock ticks (divide by
    // sysconf(_SC_CLK_TCK)).  This includes guest time,
    // guest_time (time spent running a virtual CPU, see
    // below), so that applications that are not aware of
    // the guest time field do not lose that time from
    // their calculations.
    pub(crate) utime: u64,

    // Amount of time that this process has been scheduled
    // in kernel mode, measured in clock ticks (divide by
    // sysconf(_SC_CLK_TCK)).
    pub(crate) stime: u64,

    // Amount of time that this process's waited-for chil‐
    // dren have been scheduled in user mode, measured in
    // clock ticks (divide by sysconf(_SC_CLK_TCK)).  (See
    // also times(2).)  This includes guest time,
    // cguest_time (time spent running a virtual CPU, see
    // below).
    pub(crate) cutime: u64,

    // Amount of time that this process's waited-for chil‐
    // dren have been scheduled in kernel mode, measured in
    // clock ticks (divide by sysconf(_SC_CLK_TCK)).
    pub(crate) cstime: u64,

    // The nice value (see setpriority(2)), a value in the
    // range 19 (low priority) to -20 (high priority).
    pub(crate) nice: u64,

    // User Id.
    pub(crate) uid: u64,

    // Group Id.
    pub(crate) gid: u32,

    // Current signal.
    pub(crate) cursig: u16,

    // Blocked signal.
    pub(crate) sighold: u64,

    // Pending signal.
    pub(crate) sigpend: u64,

    pub(crate) arch_state: Box<arch::ArchState>,
}

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
