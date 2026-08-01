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
//!
//! ## Modes
//!
//! `--mode locked` is the scheduling-only control: its working set is
//! pre-faulted and then `mlockall`'d, so it can never major-fault. `--mode
//! touch` is the treatment: the same working set, left unlocked and
//! actively re-touched every tick (plus a small file-backed mapping), so it
//! stays eligible for eviction and refault under pressure. One process
//! cannot measure both signals — see the crate-level doc in `lib.rs` for
//! why — so the harness runs this pair and takes the difference.

use clap::Parser;
use harness::proc_parse::{parse_majflt, parse_schedstat_wait_ns};
use harness::{ProbeMode, Tick};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Working-set and file-mapping touches operate one byte per page: enough
/// to force the kernel to resolve (and, if evicted, refault) each page,
/// without formatting or allocating.
const PAGE_SIZE: usize = 4096;

/// A fixed-size, read-only mapping of (a prefix of) a file, used by
/// `--mode touch` to keep file-backed pages in play alongside the
/// anonymous working set.
struct FileMapping {
    ptr: *mut libc::c_void,
    len: usize,
}

impl FileMapping {
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is a valid PROT_READ/MAP_PRIVATE mapping of `len`
        // bytes, established by `mmap` in `map_file` and unmapped only in
        // `Drop`, so it stays valid for the lifetime of this borrow.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for FileMapping {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` are exactly the region returned by the
        // `mmap` call that created this mapping.
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

/// Map up to 1 MiB of `path` read-only, `MAP_PRIVATE`. The file descriptor
/// does not need to outlive the call: once `mmap` succeeds, the mapping is
/// independent of the fd.
fn map_file(path: &str) -> std::io::Result<FileMapping> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let len = std::cmp::min(file_len, 1024 * 1024).max(1) as usize;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileMapping { ptr, len })
}

/// Touch (write) one byte per page of `bytes`. Uses `write_volatile`
/// rather than a plain slice write: a plain repeated write with no
/// subsequent read is a no-observable-effect store the compiler is
/// licensed to eliminate across loop iterations, which would silently
/// turn this into a no-op and stop pre-faulting/re-touching anything.
fn touch_pages_write(bytes: &mut [u8]) {
    for page_start in (0..bytes.len()).step_by(PAGE_SIZE) {
        unsafe {
            std::ptr::write_volatile(bytes.as_mut_ptr().add(page_start), 0u8);
        }
    }
}

/// Touch (read) one byte per page of `bytes`. `read_volatile` for the same
/// reason as `touch_pages_write`: an unused plain read is eligible for
/// elimination, and eliminating it would defeat the point of re-touching
/// file pages every tick.
fn touch_pages_read(bytes: &[u8]) {
    for page_start in (0..bytes.len()).step_by(PAGE_SIZE) {
        unsafe {
            std::ptr::read_volatile(bytes.as_ptr().add(page_start));
        }
    }
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)` — pins every page currently mapped
/// and every page mapped in the future, so a `locked`-mode probe can never
/// major-fault.
fn try_mlockall() -> std::io::Result<()> {
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Parser, Debug)]
#[command(name = "rlm-probe")]
struct Args {
    /// Sleep-loop wake-up interval, in milliseconds.
    #[arg(long, default_value_t = 50)]
    interval_ms: u64,

    /// Total run duration, in seconds.
    #[arg(long, default_value_t = 60)]
    duration_s: u64,

    /// Output path for JSON-lines: a header object on line 1, then one
    /// `Tick` object per subsequent line.
    #[arg(long)]
    out: String,

    /// Free-text label for this probe instance, carried into the header
    /// and later report tooling.
    #[arg(long, default_value = "")]
    label: String,

    /// Which half of the probe pair to run: `locked` (scheduling-only
    /// control) or `touch` (memory-pressure treatment).
    #[arg(long, value_enum)]
    mode: ProbeMode,

    /// Size of the anonymous working set, in mebibytes. Pre-faulted before
    /// the loop in both modes; `locked` pins it with `mlockall`, `touch`
    /// re-touches it every tick.
    #[arg(long, default_value_t = 2)]
    working_set_mb: u64,

    /// File to memory-map (up to 1 MiB) and re-touch every tick in
    /// `--mode touch`, to keep file-backed pages in play alongside the
    /// anonymous working set. Ignored in `--mode locked`.
    #[arg(long, default_value = "/proc/self/exe")]
    file: String,

    /// Free-text label for the cgroup slice this probe was placed under
    /// (set by the runner; not read from `/proc` by the probe itself).
    /// Carried into the header as `slice`.
    #[arg(long, default_value = "")]
    slice_label: String,
}

fn main() {
    let args = Args::parse();

    if args.interval_ms == 0 {
        eprintln!("error: --interval-ms must be greater than 0 (busy-spin prevention)");
        std::process::exit(1);
    }

    let interval = Duration::from_millis(args.interval_ms);
    let capacity = (args.duration_s * 1000 / args.interval_ms) as usize + 16;

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

    // Anonymous working set, common to both modes. Pre-fault it (one byte
    // per page) here, before the loop and before `mlockall`, so neither
    // mode's first tick measures its own first-touch faults, and so that
    // `mlockall` (locked mode) has nothing left to fault in.
    let mut working_set = vec![0u8; (args.working_set_mb as usize) * 1024 * 1024];
    touch_pages_write(&mut working_set);

    // Mode-specific setup. `locked` must exit non-zero if it cannot
    // actually lock — a silently-unlocked "locked" probe would corrupt the
    // whole comparison by measuring the same thing as the treatment arm.
    let mlock_ok = match args.mode {
        ProbeMode::Locked => {
            if let Err(e) = try_mlockall() {
                eprintln!(
                    "error: mlockall(MCL_CURRENT | MCL_FUTURE) failed: {e}\n\
                     The locked-mode control probe requires every page to stay \
                     resident so it can never major-fault; this almost always \
                     means RLIMIT_MEMLOCK is too low for this user. Check it \
                     with `ulimit -l` and raise it (e.g. `ulimit -l unlimited`, \
                     or LimitMEMLOCK=infinity under systemd), then retry."
                );
                std::process::exit(1);
            }
            true
        }
        ProbeMode::Touch => false,
    };

    let file_mapping = match args.mode {
        ProbeMode::Touch => match map_file(&args.file) {
            Ok(mapping) => {
                // Warm up the mapping before the loop for the same reason
                // the working set is pre-faulted: the first tick shouldn't
                // pay for this probe's own setup.
                touch_pages_read(mapping.as_slice());
                Some(mapping)
            }
            Err(e) => {
                eprintln!("error: failed to mmap --file {}: {e}", args.file);
                std::process::exit(1);
            }
        },
        ProbeMode::Locked => None,
    };

    // Buffers reused every iteration; cleared, never reallocated.
    let mut schedstat_buf = String::with_capacity(256);
    let mut stat_buf = String::with_capacity(512);

    let mut schedstat_file = File::open("/proc/self/schedstat").expect("open /proc/self/schedstat");
    let mut stat_file = File::open("/proc/self/stat").expect("open /proc/self/stat");

    let start = Instant::now();
    let mut tick_count = 0usize;
    let mut next_wake = start + interval;
    let duration = Duration::from_secs(args.duration_s);

    // Counters for parse failures (kept allocation-free inside the loop).
    let mut schedstat_failures: u64 = 0;
    let mut majflt_failures: u64 = 0;

    while start.elapsed() < duration && tick_count < ticks.len() {
        let now = Instant::now();
        if next_wake > now {
            std::thread::sleep(next_wake - now);
        }

        // Touch mode's whole point: pages that are NOT locked can be
        // reclaimed between ticks, so re-touching them here is what makes
        // this mode's drift/majflt sensitive to memory pressure. This
        // touches only pre-allocated memory — no allocation, no
        // formatting, no logging.
        if args.mode == ProbeMode::Touch {
            touch_pages_write(&mut working_set);
            if let Some(mapping) = &file_mapping {
                touch_pages_read(mapping.as_slice());
            }
        }

        let actual_elapsed = start.elapsed();

        // Stop before emitting a tick that would exceed the requested duration.
        if actual_elapsed > duration {
            break;
        }

        let intended_elapsed = interval * (tick_count as u32 + 1);
        let drift_us = actual_elapsed.as_micros() as i64 - intended_elapsed.as_micros() as i64;

        schedstat_buf.clear();
        schedstat_file
            .read_to_string(&mut schedstat_buf)
            .expect("read /proc/self/schedstat");
        seek_to_start(&mut schedstat_file);
        let wait_ns = match parse_schedstat_wait_ns(&schedstat_buf) {
            Some(val) => val,
            None => {
                schedstat_failures += 1;
                0
            }
        };

        stat_buf.clear();
        stat_file
            .read_to_string(&mut stat_buf)
            .expect("read /proc/self/stat");
        seek_to_start(&mut stat_file);
        let majflt = match parse_majflt(&stat_buf) {
            Some(val) => val,
            None => {
                majflt_failures += 1;
                0
            }
        };

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

    // Emit parse failure warnings to stderr if any occurred.
    if schedstat_failures > 0 {
        eprintln!(
            "warning: {} parse failures reading /proc/self/schedstat",
            schedstat_failures
        );
    }
    if majflt_failures > 0 {
        eprintln!(
            "warning: {} parse failures reading /proc/self/stat (majflt field)",
            majflt_failures
        );
    }

    // All formatting and I/O happens here, after the loop — never inside it.
    let out_file = File::create(&args.out).expect("create --out file");
    let mut writer = BufWriter::new(out_file);

    // Header line (line 1 of --out): one object carrying both this task's
    // probe-identity fields and Task 1's parse-failure counters. Every
    // subsequent line is a `Tick` — downstream tooling parses against
    // that "line 1 is the header" contract, so there is exactly one
    // header line, never two.
    let header = serde_json::json!({
        "label": args.label,
        "mode": args.mode,
        "interval_ms": args.interval_ms,
        "working_set_mb": args.working_set_mb,
        "mlock_ok": mlock_ok,
        "slice": args.slice_label,
        "schedstat_failures": schedstat_failures,
        "majflt_failures": majflt_failures,
    });
    serde_json::to_writer(&mut writer, &header).expect("serialize header");
    writer.write_all(b"\n").expect("write newline");

    // Write tick data.
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
