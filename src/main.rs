use clap::Parser;
use crossbeam_channel::{bounded, Sender};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rayon::prelude::*;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "asdf-vanity-grinder")]
#[command(about = "High-performance Solana vanity address generator")]
struct Args {
    /// Suffix to match (case-insensitive)
    #[arg(long, default_value = "ASDF")]
    suffix: String,

    /// Number of vanity addresses to generate
    #[arg(long, default_value_t = 10)]
    count: usize,

    /// Output JSON file
    #[arg(long, default_value = "vanity_mints.json")]
    output: String,

    /// Number of threads (default: all cores)
    #[arg(long)]
    threads: Option<usize>,

    /// Batch size for parallel processing
    #[arg(long, default_value_t = 10000)]
    batch_size: usize,
}

#[derive(Serialize, Debug)]
struct VanityResult {
    public_key: String,
    secret_key: String,
    attempts: u64,
}

fn generate_vanity_keypair(suffix_upper: &str) -> Option<(String, String)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b58 = bs58::encode(verifying_key.as_bytes()).into_string();

    if pubkey_b58.to_uppercase().ends_with(suffix_upper) {
        // Create 64-byte secret key: 32 bytes private seed + 32 bytes public key
        let mut full_secret = [0u8; 64];
        full_secret[..32].copy_from_slice(&signing_key.to_bytes());
        full_secret[32..].copy_from_slice(verifying_key.as_bytes());
        let secret_b58 = bs58::encode(&full_secret).into_string();
        Some((pubkey_b58, secret_b58))
    } else {
        None
    }
}

fn main() {
    let args = Args::parse();
    let suffix_upper = args.suffix.to_uppercase();
    let target_count = args.count;

    // Configure thread pool
    let num_threads = args.threads.unwrap_or_else(num_cpus::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .expect("Failed to build thread pool");

    println!("Solana Vanity Address Generator");
    println!("================================");
    println!("Suffix: {} (case-insensitive)", args.suffix);
    println!("Target count: {}", target_count);
    println!("Threads: {}", num_threads);
    println!("Batch size: {}", args.batch_size);
    println!("Output: {}", args.output);
    println!();

    // Shared state
    let attempts = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let should_stop = Arc::new(AtomicBool::new(false));

    // Channel for results
    let (sender, receiver) = bounded::<VanityResult>(target_count);

    // Stats thread
    let stats_attempts = Arc::clone(&attempts);
    let stats_found = Arc::clone(&found_count);
    let stats_stop = Arc::clone(&should_stop);
    let stats_target = target_count;
    let stats_handle = thread::spawn(move || {
        let start = Instant::now();
        let mut last_attempts = 0u64;
        let mut last_time = start;

        while !stats_stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            let current_attempts = stats_attempts.load(Ordering::Relaxed);
            let current_found = stats_found.load(Ordering::Relaxed);
            let now = Instant::now();

            let elapsed_since_last = now.duration_since(last_time).as_secs_f64();
            let attempts_since_last = current_attempts.saturating_sub(last_attempts);
            let keys_per_sec = if elapsed_since_last > 0.0 {
                (attempts_since_last as f64 / elapsed_since_last) as u64
            } else {
                0
            };

            print!(
                "\r[Stats] Attempts: {} | Speed: {} keys/sec | Found: {}/{}    ",
                current_attempts, keys_per_sec, current_found, stats_target
            );
            std::io::stdout().flush().unwrap();

            last_attempts = current_attempts;
            last_time = now;
        }
        println!();
    });

    // Worker threads using rayon
    let worker_attempts = Arc::clone(&attempts);
    let worker_found = Arc::clone(&found_count);
    let worker_stop = Arc::clone(&should_stop);
    let batch_size = args.batch_size;

    let worker_handle = thread::spawn(move || {
        grind_loop(
            &suffix_upper,
            target_count,
            batch_size,
            sender,
            worker_attempts,
            worker_found,
            worker_stop,
        );
    });

    // Collect results
    let mut results: Vec<VanityResult> = Vec::with_capacity(target_count);
    for result in receiver.iter() {
        results.push(result);
        if results.len() >= target_count {
            break;
        }
    }

    // Signal stop
    should_stop.store(true, Ordering::Relaxed);

    // Wait for threads
    let _ = worker_handle.join();
    let _ = stats_handle.join();

    // Write output
    let file = File::create(&args.output).expect("Failed to create output file");
    serde_json::to_writer_pretty(file, &results).expect("Failed to write JSON");

    println!("\nResults written to: {}", args.output);
    println!("\nGenerated addresses:");
    for (i, result) in results.iter().enumerate() {
        println!("  {}. {} (attempts: {})", i + 1, result.public_key, result.attempts);
    }
}

fn grind_loop(
    suffix_upper: &str,
    target_count: usize,
    batch_size: usize,
    sender: Sender<VanityResult>,
    attempts: Arc<AtomicU64>,
    found_count: Arc<AtomicU64>,
    should_stop: Arc<AtomicBool>,
) {
    loop {
        if should_stop.load(Ordering::Relaxed) {
            break;
        }

        let current_found = found_count.load(Ordering::Relaxed) as usize;
        if current_found >= target_count {
            break;
        }

        // Process batch in parallel
        let results: Vec<_> = (0..batch_size)
            .into_par_iter()
            .filter_map(|_| {
                if should_stop.load(Ordering::Relaxed) {
                    return None;
                }
                generate_vanity_keypair(suffix_upper)
            })
            .collect();

        // Update attempts counter
        attempts.fetch_add(batch_size as u64, Ordering::Relaxed);

        // Send results
        for (pubkey, secret) in results {
            let current = found_count.fetch_add(1, Ordering::Relaxed) as usize;
            if current >= target_count {
                break;
            }

            let result = VanityResult {
                public_key: pubkey,
                secret_key: secret,
                attempts: attempts.load(Ordering::Relaxed),
            };

            if sender.send(result).is_err() {
                return;
            }
        }
    }
}
