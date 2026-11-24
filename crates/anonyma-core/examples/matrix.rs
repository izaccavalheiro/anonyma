//! The Rust core's cells of the benchmark matrix (bench/matrix/), on the corpus
//! that bench/matrix/corpus.mjs writes, in the rows every harness writes.
//!
//! ```text
//! cargo run --release -p anonyma-core --features parallel --example matrix -- <corpus dir> <out.jsonl>
//! ```

use std::fmt::Write as _;
use std::hint::black_box;
use std::path::Path;
use std::time::{Duration, Instant};

use anonyma_core::AnonymaEngine;

/// Median milliseconds of one run of `run`, over at least 5 runs and 300 ms.
fn median(mut run: impl FnMut()) -> f64 {
    run();
    let mut samples = Vec::new();
    let start = Instant::now();
    while samples.len() < 5 || (start.elapsed() < Duration::from_millis(300) && samples.len() < 50)
    {
        let t = Instant::now();
        run();
        samples.push(t.elapsed().as_secs_f64() * 1e3);
    }
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

#[allow(clippy::too_many_arguments)]
fn row(
    out: &mut String,
    shape: &str,
    entry_size: usize,
    entries: usize,
    threads: usize,
    median_ms: f64,
    matches: usize,
) {
    let line = format!(
        "{{\"engine\":\"rust\",\"runtime\":\"rustc release\",\"op\":\"detect\",\"shape\":\"{shape}\",\
         \"entrySize\":{entry_size},\"entries\":{entries},\"threads\":{threads},\
         \"medianMs\":{median_ms},\"perEntryUs\":{},\"matches\":{matches}}}",
        median_ms * 1000.0 / entries as f64
    );
    println!("{line}");
    writeln!(out, "{line}").expect("a string");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(dir), Some(out_path)) = (args.next(), args.next()) else {
        eprintln!("usage: matrix <corpus dir> <out.jsonl>");
        std::process::exit(2);
    };
    let dir = Path::new(&dir);
    let engine = AnonymaEngine::builder().build().expect("every category");
    let mut out = String::new();

    for name in ["1k", "100k", "1m"] {
        let text = std::fs::read_to_string(dir.join(format!("single-{name}.txt"))).expect("corpus");
        let matches = engine.detect(&text).len();
        let ms = median(|| {
            black_box(engine.detect(&text));
        });
        row(&mut out, "single", text.len(), 1, 1, ms, matches);
    }

    let json = std::fs::read_to_string(dir.join("entries.json")).expect("corpus");
    let entries: Vec<String> = serde_json::from_str(&json).expect("a JSON array of strings");
    let size = entries.iter().map(String::len).sum::<usize>() / entries.len();
    let each: usize = entries.iter().map(|e| engine.detect(e).len()).sum();
    let ms = median(|| {
        for e in &entries {
            black_box(engine.detect(e));
        }
    });
    row(&mut out, "each", size, entries.len(), 1, ms, each);

    // The same calls spread over threads, one engine shared by all.
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    let mut counts = vec![2, 4, cores];
    counts.retain(|&n| n > 1 && n <= cores);
    counts.dedup();
    for threads in counts {
        let chunk = entries.len().div_ceil(threads);
        let ms = median(|| {
            std::thread::scope(|scope| {
                for part in entries.chunks(chunk) {
                    let engine = &engine;
                    scope.spawn(move || {
                        for e in part {
                            black_box(engine.detect(e));
                        }
                    });
                }
            });
        });
        row(&mut out, "each", size, entries.len(), threads, ms, each);
    }

    // With the `parallel` feature, a batch runs on rayon's pool.
    let threads = if cfg!(feature = "parallel") {
        std::thread::available_parallelism().map_or(1, usize::from)
    } else {
        1
    };
    let batch: usize = engine.detect_batch(&entries).iter().map(Vec::len).sum();
    let ms = median(|| {
        black_box(engine.detect_batch(&entries));
    });
    row(&mut out, "batch", size, entries.len(), threads, ms, batch);

    std::fs::write(out_path, out).expect("the output file");
}
