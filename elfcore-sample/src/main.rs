// Copyright (C) Microsoft Corporation.
// Licensed under the MIT License.

//! Sample process for writing core dumps.
//!
//! `elfcore-sample <pid> <output_path>`
//!
//! This command writes a core dump of process `pid` to `output_path`.
//!
//! An optional `-v` parameter may be specified before any options to enable
//! debug level tracing.
//!

#![cfg(target_os = "linux")]

use anyhow::Context;
use std::path::PathBuf;
use tracing::Level;

pub fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();

    let level = if args.peek().map_or(false, |x| x == "-v") {
        args.next();
        Level::DEBUG
    } else {
        Level::WARN
    };

    let pid: i32 = args
        .next()
        .context("missing pid")?
        .parse()
        .context("failed to parse pid")?;

    let output_path: PathBuf = args
        .next()
        .context("missing output_path")?
        .parse()
        .context("failed to parse output_path")?;

    if args.next().is_some() {
        anyhow::bail!("unexpected extra arguments");
    }

    let output_file = std::fs::File::create(output_path).context("unable to create output file")?;

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .init();

    let process_view =
        elfcore::ProcessView::new(pid).context("failed to prepare process for core dump")?;

    let n = elfcore::write_core_dump(output_file, &process_view, None)
        .context("failed to write core dump")?;

    tracing::debug!("wrote {} bytes", n);
    Ok(())
}
