//! `rlm-probe` — fixed-interval sleep loop that records, per iteration, how
//! far the wake-up drifted from schedule, plus two decomposition signals:
//! runqueue wait (`/proc/self/schedstat`) and major faults
//! (`/proc/self/stat`).
//!
//! The measurement loop below must not allocate: allocation under memory
//! pressure is exactly what this probe exists to measure, so a probe that
//! allocates in its own hot loop would be measuring itself. To that end:
//! the `Vec<Tick>` is sized and filled (not pushed) before the loop starts,
//! and the two `/proc` reads reuse the same `String` buffers every
//! iteration (`String::clear()` then `File::read_to_string`, since
//! `read_to_string` appends rather than overwrites). No formatting or
//! logging happens inside the loop; all output is written after it ends.

use clap::Parser;
use harness::proc_parse::{parse_majflt, parse_schedstat_wait_ns};
use harness::Tick;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "rlm-probe")]
struct Args {
    /// Sleep-loop wake-up interval, in milliseconds.
    #[arg(long, default_value_t = 50)]
    interval_ms: u64,

    /// Total run duration, in seconds.
    #[arg(long, default_value_t = 60)]
    duration_s: u64,

    /// Output path for JSON-lines of `Tick`.
    #[arg(long)]
    out: String,

    /// Free-text label for this probe instance, carried into later report
    /// tooling (not written by Task 1's bare loop, but parsed now so the
    /// CLI surface is stable across tasks).
    #[arg(long, default_value = "")]
    label: String,
}

fn main() {
    let args = Args::parse();

    let interval = Duration::from_millis(args.interval_ms);
    let capacity = (args.duration_s * 1000 / args.interval_ms.max(1)) as usize + 16;

    // Pre-allocate every tick slot before the loop starts. `resize` (not
    // `with_capacity`) so the loop below only ever writes into existing
    // slots by index — no `push`, no reallocation, no growth.
    let mut ticks: Vec<Tick> = Vec::new();
    ticks.resize(
        capacity,
        Tick {
            t_ms: 0,
            drift_us: 0,
            wait_ns: 0,
            majflt: 0,
        },
    );

    // Buffers reused every iteration; cleared, never reallocated.
    let mut schedstat_buf = String::with_capacity(256);
    let mut stat_buf = String::with_capacity(512);

    let mut schedstat_file = File::open("/proc/self/schedstat").expect("open /proc/self/schedstat");
    let mut stat_file = File::open("/proc/self/stat").expect("open /proc/self/stat");

    let start = Instant::now();
    let mut tick_count = 0usize;
    let mut next_wake = start + interval;

    while start.elapsed() < Duration::from_secs(args.duration_s) && tick_count < ticks.len() {
        let now = Instant::now();
        if next_wake > now {
            std::thread::sleep(next_wake - now);
        }

        let actual_elapsed = start.elapsed();
        let intended_elapsed = interval * (tick_count as u32 + 1);
        let drift_us = actual_elapsed.as_micros() as i64 - intended_elapsed.as_micros() as i64;

        schedstat_buf.clear();
        schedstat_file
            .read_to_string(&mut schedstat_buf)
            .expect("read /proc/self/schedstat");
        seek_to_start(&mut schedstat_file);
        let wait_ns = parse_schedstat_wait_ns(&schedstat_buf).unwrap_or(0);

        stat_buf.clear();
        stat_file
            .read_to_string(&mut stat_buf)
            .expect("read /proc/self/stat");
        seek_to_start(&mut stat_file);
        let majflt = parse_majflt(&stat_buf).unwrap_or(0);

        ticks[tick_count] = Tick {
            t_ms: actual_elapsed.as_millis() as u64,
            drift_us,
            wait_ns,
            majflt,
        };
        tick_count += 1;
        next_wake += interval;
    }

    ticks.truncate(tick_count);

    // All formatting and I/O happens here, after the loop — never inside it.
    let out_file = File::create(&args.out).expect("create --out file");
    let mut writer = BufWriter::new(out_file);
    for tick in &ticks {
        serde_json::to_writer(&mut writer, tick).expect("serialize tick");
        writer.write_all(b"\n").expect("write newline");
    }
    writer.flush().expect("flush output");
}

/// `/proc` files report cumulative counters; re-reading a fresh snapshot
/// each iteration means seeking back to the start rather than reopening
/// (reopening would allocate a new fd's worth of kernel state per tick,
/// and this whole function exists to avoid per-tick allocation).
fn seek_to_start(file: &mut File) {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).expect("seek to start");
}
