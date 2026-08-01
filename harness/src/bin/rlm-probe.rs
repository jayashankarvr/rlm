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
//!
//! ## Symmetric control walk
//!
//! Both modes walk the entire working set every tick with the *same*
//! function (`touch_pages_write`, same stride, same byte count, same
//! order) — in `locked` mode the working set is mlocked, so the walk can
//! never fault, but it costs the same CPU as `touch` mode's walk. That
//! shared CPU cost cancels out in `touch − locked`, so it stops being
//! misattributed to memory-induced stall. Only `touch` mode additionally
//! re-reads the file-backed mapping every tick — that asymmetry is
//! intentional, it's the whole point of the treatment arm. Consequently
//! the residual `touch − locked` is the file-backed-reclaim component plus
//! any anon-reclaim effect the two walks' identical CPU cost doesn't
//! explain — not scheduling noise from unequal per-tick work.

use clap::Parser;
use harness::proc_parse::{parse_majflt, parse_schedstat_wait_ns};
use harness::{ProbeMode, Tick};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
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

/// RAII guard for a scratch file: unlinks the file on drop, ensuring cleanup
/// even if an error or early return happens before the unlink.
struct ScratchFileGuard {
    path: Option<PathBuf>,
}

impl ScratchFileGuard {
    fn new(path: PathBuf) -> Self {
        ScratchFileGuard { path: Some(path) }
    }

    /// Get a reference to the path (if not yet released).
    fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    /// Consume the guard without unlinking (the file is kept); prevents
    /// Drop from attempting to unlink again.
    fn release(mut self) {
        self.path = None;
    }
}

impl Drop for ScratchFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Map up to `max_mb` MiB of `path` read-only, `MAP_PRIVATE`. The file
/// descriptor does not need to outlive the call: once `mmap` succeeds, the
/// mapping is independent of the fd.
fn map_file(path: &str, max_mb: u64) -> std::io::Result<FileMapping> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();

    // Reject zero-length backing files: mmap with len=0 is an error, but
    // mmap with len>0 on a zero-length file succeeds and produces an
    // unreadable mapping. Dereferencing it causes SIGBUS. Bail out cleanly.
    if file_len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("backing file {} is zero-length (cannot mmap)", path),
        ));
    }

    let max_len = max_mb.saturating_mul(1024 * 1024);
    let len = std::cmp::min(file_len, max_len) as usize;

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

/// Create a dedicated scratch file for `--mode touch`'s file-backed
/// mapping: `size_mb` MiB of non-compressible bytes (a simple xorshift
/// stream, so a filesystem/device with transparent compression can't
/// collapse it to a handful of physical pages), written into `dir`,
/// `fsync`'d so the content is actually durable, then best-effort dropped
/// from the page cache with `posix_fadvise(POSIX_FADV_DONTNEED)` so the
/// probe's own write doesn't leave the mapping pre-warmed. Returns the
/// path and the still-open `File` (kept open only so the caller can mmap
/// it; the file's directory entry is removed by the caller once the
/// mapping is established). On any failure the partially-written file is
/// removed before returning the error — this function never leaves a
/// scratch file behind on an error path.
fn create_scratch_file(dir: &Path, size_mb: u64) -> std::io::Result<(PathBuf, File)> {
    let path = dir.join(format!("rlm-probe-scratch-{}.bin", std::process::id()));

    let result = (|| -> std::io::Result<File> {
        let mut file = File::create(&path)?;
        let mut buf = vec![0u8; PAGE_SIZE];
        let size_bytes = (size_mb as usize) * 1024 * 1024;
        // xorshift32 requires a non-zero seed; OR in 1 so an unlucky PID
        // can't zero it out and collapse the stream to all-zero bytes.
        let mut state: u32 = (0x9E37_79B9 ^ std::process::id()) | 1;
        let mut written = 0usize;
        while written < size_bytes {
            for word in buf.chunks_mut(4) {
                // xorshift32: cheap, deterministic-per-run, and non-repeating
                // over a single page — good enough to defeat compression
                // without pulling in a `rand` dependency for a one-time
                // setup step outside the measurement loop.
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let bytes = state.to_le_bytes();
                word.copy_from_slice(&bytes[..word.len()]);
            }
            file.write_all(&buf)?;
            written += buf.len();
        }
        file.sync_all()?;

        // Best-effort: not fatal if unsupported (e.g. tmpfs) or denied.
        // Portable without root — unlike dropping another process's cached
        // pages, fadvise on a file this process just created and owns
        // needs no special privilege.
        unsafe {
            libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
        }

        Ok(file)
    })();

    match result {
        Ok(file) => Ok((path, file)),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
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

    /// File to memory-map (up to `--file-mb` MiB) and re-touch every tick
    /// in `--mode touch`, to keep file-backed pages in play alongside the
    /// anonymous working set. If omitted, the probe creates, owns, and
    /// deletes its own dedicated scratch file (see `--file-mb`) — do NOT
    /// point this at `/proc/self/exe` or any other binary the probe (or
    /// anything else) is actively executing: the kernel's LRU is least
    /// likely to reclaim actively-executing code pages, so re-reading them
    /// silently understates file-backed reclaim sensitivity instead of
    /// measuring it. Ignored in `--mode locked`.
    #[arg(long)]
    file: Option<String>,

    /// Size, in mebibytes, of the dedicated scratch file `--mode touch`
    /// creates when `--file` is not given, and the cap on how much of any
    /// `--file` (dedicated or user-supplied) gets mapped and re-touched.
    #[arg(long, default_value_t = 1)]
    file_mb: u64,

    /// Free-text label for the cgroup slice this probe was placed under
    /// (set by the runner; not read from `/proc` by the probe itself).
    /// Carried into the header as `slice`.
    #[arg(long, default_value = "")]
    slice_label: String,
}

fn main() {
    let args = Args::parse();

    // All fallible work lives in `run`, which returns `Err` instead of
    // calling `std::process::exit` directly. `std::process::exit` does not
    // run destructors for live stack values (it's not `panic!`, which
    // unwinds), so any RAII guard live at the moment of exit — e.g.
    // `ScratchFileGuard` — would silently skip its cleanup. Returning from
    // `run` instead lets every guard drop normally before `main` decides
    // whether to exit non-zero, closing that hazard for this exit path and
    // any future early-return added inside `run`.
    if let Err(e) = run(args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.interval_ms == 0 {
        return Err("--interval-ms must be greater than 0 (busy-spin prevention)".into());
    }

    if args.file_mb == 0 {
        return Err("--file-mb must be greater than 0 (zero-length mmap prevention)".into());
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
                return Err(format!(
                    "mlockall(MCL_CURRENT | MCL_FUTURE) failed: {e}\n\
                     The locked-mode control probe requires every page to stay \
                     resident so it can never major-fault. MCL_CURRENT locks the \
                     process's *entire* current mapping set — binary text, \
                     shared libraries, and stack, not just --working-set-mb — so \
                     size RLIMIT_MEMLOCK well above --working-set-mb alone. This \
                     almost always means RLIMIT_MEMLOCK is too low for this \
                     user. Check it with `ulimit -l` and raise it (e.g. `ulimit \
                     -l unlimited`, or LimitMEMLOCK=infinity under systemd), \
                     then retry."
                )
                .into());
            }
            true
        }
        ProbeMode::Touch => false,
    };

    // If `--mode touch` and no `--file` was given, create a dedicated
    // scratch file rather than defaulting to something like
    // `/proc/self/exe`: re-reading the probe's own executing code would
    // measure pages the kernel's LRU is least likely to ever reclaim,
    // understating file-backed reclaim sensitivity instead of measuring
    // it. `_scratch_guard` holds the path and unlinks it on drop (RAII),
    // so cleanup is guaranteed even if an error occurs; a user-supplied
    // `--file` is never deleted.
    let mut _scratch_guard: Option<ScratchFileGuard> = None;
    let file_path: Option<String> = match args.mode {
        ProbeMode::Touch => match &args.file {
            Some(p) => Some(p.clone()),
            None => {
                let out_dir = Path::new(&args.out)
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                match create_scratch_file(out_dir, args.file_mb) {
                    Ok((path, _file)) => {
                        let p = path
                            .to_str()
                            .expect("scratch path is valid UTF-8")
                            .to_string();
                        _scratch_guard = Some(ScratchFileGuard::new(path));
                        Some(p)
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to create scratch file for --mode touch's \
                             file-backed mapping: {e}"
                        )
                        .into());
                    }
                }
            }
        },
        ProbeMode::Locked => None,
    };

    let file_mapping = match &file_path {
        Some(path) => match map_file(path, args.file_mb) {
            Ok(mapping) => {
                // Warm up the mapping before the loop for the same reason
                // the working set is pre-faulted: the first tick shouldn't
                // pay for this probe's own setup.
                touch_pages_read(mapping.as_slice());
                // The mapping now holds the inode open, so it's safe (and
                // required, to satisfy "delete on exit including error
                // paths") to unlink our own scratch file's directory entry
                // right away rather than waiting for process exit — the
                // kernel keeps the inode alive as long as it's mapped.
                if let Some(guard) = _scratch_guard.take() {
                    // Manually unlink the file, then release the guard to
                    // prevent Drop from unlinking it again. The inode
                    // stays alive as long as it's mapped.
                    if let Some(path) = guard.path() {
                        let _ = std::fs::remove_file(path);
                    }
                    guard.release();
                }
                Some(mapping)
            }
            Err(e) => {
                // Returning here (instead of `std::process::exit`) lets
                // `_scratch_guard` drop normally before `main` exits, which
                // unlinks the scratch file. `std::process::exit` does not run
                // destructors, so calling it here with `_scratch_guard` still
                // live would leak the scratch file on disk.
                return Err(format!("failed to mmap --file {path}: {e}").into());
            }
        },
        None => None,
    };

    // Buffers reused every iteration; cleared, never reallocated. Both are
    // allocated after `mlockall(MCL_FUTURE)` above (locked mode), so their
    // backing pages count against the locked memory budget — harmless: a
    // one-time, sub-page-rounded, pre-loop allocation, not part of the
    // measured working set.
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

        // Symmetric control walk (see module doc): BOTH modes re-touch the
        // whole working set every tick, with the same function, stride,
        // byte count, and order, so this walk's CPU cost is identical in
        // both modes and cancels in `touch − locked`. In `locked` mode the
        // working set is mlocked, so the walk can never fault — only the
        // CPU cost is symmetric, not the fault behaviour. This touches
        // only pre-allocated memory — no allocation, no formatting, no
        // logging.
        touch_pages_write(&mut working_set);

        // Only `touch` mode re-reads the file-backed mapping: pages that
        // are NOT locked can be reclaimed between ticks, so re-touching
        // them here is what makes this mode's drift/majflt sensitive to
        // memory pressure. This asymmetry vs. `locked` (which has no file
        // mapping at all) is intentional — it's the treatment's whole
        // point — so it is the one component that legitimately survives
        // into the `touch − locked` residual.
        if let Some(mapping) = &file_mapping {
            touch_pages_read(mapping.as_slice());
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
        // True iff this build performs the symmetric control walk (both
        // modes re-touch the working set every tick, so the walk's CPU
        // cost cancels in `touch − locked`). Always true as of this field
        // existing; downstream tooling should treat its *absence* as
        // "unknown, possibly biased" rather than assuming symmetry.
        "symmetric_walk": true,
    });
    serde_json::to_writer(&mut writer, &header).expect("serialize header");
    writer.write_all(b"\n").expect("write newline");

    // Write tick data.
    for tick in &ticks {
        serde_json::to_writer(&mut writer, tick).expect("serialize tick");
        writer.write_all(b"\n").expect("write newline");
    }
    writer.flush().expect("flush output");

    Ok(())
}

/// `/proc` files report cumulative counters; re-reading a fresh snapshot
/// each iteration means seeking back to the start rather than reopening
/// (reopening would allocate a new fd's worth of kernel state per tick,
/// and this whole function exists to avoid per-tick allocation).
fn seek_to_start(file: &mut File) {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).expect("seek to start");
}
