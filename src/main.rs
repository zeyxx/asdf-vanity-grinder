use clap::{Parser, Subcommand};
use crossbeam_channel::bounded;
use ed25519_dalek::SigningKey;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server};

#[derive(Parser, Debug)]
#[command(name = "asdf-vanity-grinder")]
#[command(about = "High-performance Solana vanity address generator with pool server mode")]
#[command(version = "2.0.0")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate vanity keypairs and save to file
    Generate {
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
    },
    /// Start HTTP pool server for ASDev integration
    Pool {
        /// Pool JSON file path
        #[arg(long, default_value = "vanity_mints.json")]
        file: String,

        /// HTTP server port
        #[arg(long, default_value_t = 3030)]
        port: u16,

        /// Suffix for new keypairs (case-insensitive)
        #[arg(long, default_value = "ASDF")]
        suffix: String,

        /// Number of threads for generation (default: all cores)
        #[arg(long)]
        threads: Option<usize>,

        /// Minimum pool size before auto-refill warning
        #[arg(long, default_value_t = 10)]
        min_pool: usize,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VanityMint {
    /// Token mint address (public key) ending with suffix
    mint_address: String,
    /// Full 64-byte keypair (32 private + 32 public) in base58
    mint_keypair: String,
    /// Whether this keypair has been used for a token launch
    used: bool,
    /// Number of attempts to find this keypair
    #[serde(default)]
    attempts: u64,
}

#[derive(Serialize)]
struct PoolStats {
    total: usize,
    available: usize,
    used: usize,
    suffix: String,
}

#[derive(Serialize)]
struct MintResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mint: Option<VanityMint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    remaining: usize,
}

#[derive(Serialize)]
struct RefillResponse {
    success: bool,
    generated: usize,
    total_available: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn generate_vanity_keypair(suffix_upper: &str) -> Option<(String, String)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b58 = bs58::encode(verifying_key.as_bytes()).into_string();

    if pubkey_b58.to_uppercase().ends_with(suffix_upper) {
        let mut full_secret = [0u8; 64];
        full_secret[..32].copy_from_slice(&signing_key.to_bytes());
        full_secret[32..].copy_from_slice(verifying_key.as_bytes());
        let secret_b58 = bs58::encode(&full_secret).into_string();
        Some((pubkey_b58, secret_b58))
    } else {
        None
    }
}

fn generate_keypairs_batch(suffix: &str, count: usize, threads: Option<usize>, show_progress: bool) -> Vec<VanityMint> {
    let suffix_upper = suffix.to_uppercase();
    let num_threads = threads.unwrap_or_else(num_cpus::get);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .ok(); // Ignore if already built

    let attempts = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let should_stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = bounded::<VanityMint>(count);

    // Stats thread (only if showing progress)
    let stats_handle = if show_progress {
        let stats_attempts = Arc::clone(&attempts);
        let stats_found = Arc::clone(&found_count);
        let stats_stop = Arc::clone(&should_stop);
        Some(thread::spawn(move || {
            let mut last_attempts = 0u64;
            let mut last_time = Instant::now();
            while !stats_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                let current_attempts = stats_attempts.load(Ordering::Relaxed);
                let current_found = stats_found.load(Ordering::Relaxed);
                let now = Instant::now();
                let elapsed = now.duration_since(last_time).as_secs_f64();
                let speed = if elapsed > 0.0 {
                    ((current_attempts - last_attempts) as f64 / elapsed) as u64
                } else { 0 };
                print!("\r[Stats] Attempts: {} | Speed: {} keys/sec | Found: {}/{}    ",
                    current_attempts, speed, current_found, count);
                std::io::stdout().flush().ok();
                last_attempts = current_attempts;
                last_time = now;
            }
            println!();
        }))
    } else {
        None
    };

    // Worker thread
    let worker_attempts = Arc::clone(&attempts);
    let worker_found = Arc::clone(&found_count);
    let worker_stop = Arc::clone(&should_stop);
    let suffix_clone = suffix_upper.clone();

    let worker_handle = thread::spawn(move || {
        let batch_size = 10000;
        loop {
            if worker_stop.load(Ordering::Relaxed) || worker_found.load(Ordering::Relaxed) as usize >= count {
                break;
            }
            let results: Vec<_> = (0..batch_size)
                .into_par_iter()
                .filter_map(|_| {
                    if worker_stop.load(Ordering::Relaxed) { return None; }
                    generate_vanity_keypair(&suffix_clone)
                })
                .collect();
            worker_attempts.fetch_add(batch_size as u64, Ordering::Relaxed);
            for (pubkey, secret) in results {
                let current = worker_found.fetch_add(1, Ordering::Relaxed) as usize;
                if current >= count { break; }
                let mint = VanityMint {
                    mint_address: pubkey,
                    mint_keypair: secret,
                    used: false,
                    attempts: worker_attempts.load(Ordering::Relaxed),
                };
                if sender.send(mint).is_err() { return; }
            }
        }
    });

    let mut results = Vec::with_capacity(count);
    for mint in receiver.iter() {
        results.push(mint);
        if results.len() >= count { break; }
    }

    should_stop.store(true, Ordering::Relaxed);
    worker_handle.join().ok();
    if let Some(h) = stats_handle { h.join().ok(); }

    results
}

fn load_pool(path: &str) -> Vec<VanityMint> {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_pool(path: &str, pool: &[VanityMint]) -> std::io::Result<()> {
    let content = serde_json::to_string_pretty(pool)?;
    fs::write(path, content)
}

fn run_generate(suffix: String, count: usize, output: String, threads: Option<usize>, batch_size: usize) {
    let num_threads = threads.unwrap_or_else(num_cpus::get);

    println!("Solana Vanity Address Generator");
    println!("================================");
    println!("Suffix: {} (case-insensitive)", suffix);
    println!("Target count: {}", count);
    println!("Threads: {}", num_threads);
    println!("Batch size: {}", batch_size);
    println!("Output: {}", output);
    println!();

    let results = generate_keypairs_batch(&suffix, count, threads, true);

    let file = File::create(&output).expect("Failed to create output file");
    serde_json::to_writer_pretty(file, &results).expect("Failed to write JSON");

    println!("\nResults written to: {}", output);
    println!("\nGenerated mint addresses:");
    for (i, mint) in results.iter().enumerate() {
        println!("  {}. {} (attempts: {})", i + 1, mint.mint_address, mint.attempts);
    }
}

fn run_pool_server(file: String, port: u16, suffix: String, threads: Option<usize>, min_pool: usize) {
    let pool: Arc<RwLock<Vec<VanityMint>>> = Arc::new(RwLock::new(load_pool(&file)));

    let available = pool.read().iter().filter(|m| !m.used).count();
    println!("ASDF Vanity Pool Server v2.0.0");
    println!("==============================");
    println!("Pool file: {}", file);
    println!("Suffix: {}", suffix);
    println!("Port: {}", port);
    println!("Pool size: {} total, {} available", pool.read().len(), available);
    println!("Min pool warning: {}", min_pool);
    println!();
    println!("Endpoints:");
    println!("  GET  /mint         - Get next available mint keypair");
    println!("  GET  /stats        - Pool statistics");
    println!("  POST /refill?count=N - Generate N new keypairs");
    println!("  GET  /health       - Health check");
    println!();
    println!("Starting server on http://0.0.0.0:{}...", port);

    let server = Server::http(format!("0.0.0.0:{}", port)).expect("Failed to start server");

    let json_header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let cors_header = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();

    for request in server.incoming_requests() {
        let pool = Arc::clone(&pool);
        let file = file.clone();
        let suffix = suffix.clone();
        let json_header = json_header.clone();
        let cors_header = cors_header.clone();

        let path = request.url().split('?').next().unwrap_or("/");
        let query: std::collections::HashMap<String, String> = request
            .url()
            .split('?')
            .nth(1)
            .unwrap_or("")
            .split('&')
            .filter_map(|p| {
                let mut parts = p.split('=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();

        let response = match (request.method(), path) {
            // Health check
            (Method::Get, "/health") => {
                Response::from_string("{\"status\":\"ok\"}")
                    .with_header(json_header)
                    .with_header(cors_header)
            }

            // Get pool stats
            (Method::Get, "/stats") => {
                let pool = pool.read();
                let stats = PoolStats {
                    total: pool.len(),
                    available: pool.iter().filter(|m| !m.used).count(),
                    used: pool.iter().filter(|m| m.used).count(),
                    suffix: suffix.clone(),
                };
                let body = serde_json::to_string(&stats).unwrap();
                Response::from_string(body)
                    .with_header(json_header)
                    .with_header(cors_header)
            }

            // Get next available mint
            (Method::Get, "/mint") => {
                let mut pool = pool.write();
                let result = if let Some(mint) = pool.iter_mut().find(|m| !m.used) {
                    mint.used = true;
                    let mint_clone = mint.clone();
                    let remaining = pool.iter().filter(|m| !m.used).count();

                    // Save to file
                    if let Err(e) = save_pool(&file, &pool) {
                        eprintln!("[WARN] Failed to save pool: {}", e);
                    }

                    // Warning if low
                    if remaining < min_pool {
                        eprintln!("[WARN] Pool running low! {} remaining (min: {})", remaining, min_pool);
                    }

                    println!("[MINT] Dispensed: {} ({} remaining)", mint_clone.mint_address, remaining);

                    MintResponse {
                        success: true,
                        mint: Some(mint_clone),
                        error: None,
                        remaining,
                    }
                } else {
                    MintResponse {
                        success: false,
                        mint: None,
                        error: Some("No available mints in pool".to_string()),
                        remaining: 0,
                    }
                };
                let body = serde_json::to_string(&result).unwrap();
                Response::from_string(body)
                    .with_header(json_header)
                    .with_header(cors_header)
            }

            // Refill pool
            (Method::Post, "/refill") => {
                let count: usize = query.get("count").and_then(|c| c.parse().ok()).unwrap_or(10);

                println!("[REFILL] Generating {} new keypairs...", count);
                let new_mints = generate_keypairs_batch(&suffix, count, threads, false);

                let mut pool = pool.write();
                pool.extend(new_mints.clone());

                if let Err(e) = save_pool(&file, &pool) {
                    let resp = RefillResponse {
                        success: false,
                        generated: 0,
                        total_available: pool.iter().filter(|m| !m.used).count(),
                        error: Some(format!("Failed to save: {}", e)),
                    };
                    let body = serde_json::to_string(&resp).unwrap();
                    request.respond(Response::from_string(body)
                        .with_header(json_header)
                        .with_header(cors_header)).ok();
                    continue;
                }

                let available = pool.iter().filter(|m| !m.used).count();
                println!("[REFILL] Generated {} keypairs. Total available: {}", count, available);

                let resp = RefillResponse {
                    success: true,
                    generated: count,
                    total_available: available,
                    error: None,
                };
                let body = serde_json::to_string(&resp).unwrap();
                Response::from_string(body)
                    .with_header(json_header)
                    .with_header(cors_header)
            }

            // CORS preflight
            (Method::Options, _) => {
                Response::from_string("")
                    .with_header(cors_header)
                    .with_header(Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap())
                    .with_header(Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap())
            }

            // 404
            _ => {
                Response::from_string("{\"error\":\"Not found\"}")
                    .with_status_code(404)
                    .with_header(json_header)
                    .with_header(cors_header)
            }
        };

        request.respond(response).ok();
    }
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Generate { suffix, count, output, threads, batch_size } => {
            run_generate(suffix, count, output, threads, batch_size);
        }
        Commands::Pool { file, port, suffix, threads, min_pool } => {
            run_pool_server(file, port, suffix, threads, min_pool);
        }
    }
}
