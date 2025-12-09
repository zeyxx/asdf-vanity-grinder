use chrono::Utc;
use clap::{Parser, Subcommand};
use crossbeam_channel::bounded;
use ed25519_dalek::SigningKey;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server};

const VERSION: &str = "2.1.0";

#[derive(Parser, Debug)]
#[command(name = "asdf-vanity-grinder")]
#[command(about = "High-performance Solana vanity address generator with secure pool server")]
#[command(version = VERSION)]
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
    /// Start secure HTTP pool server for production
    Pool {
        /// Pool JSON file path
        #[arg(long, default_value = "vanity_mints.json", env = "VANITY_POOL_FILE")]
        file: String,

        /// HTTP server port
        #[arg(long, default_value_t = 3030, env = "VANITY_POOL_PORT")]
        port: u16,

        /// Suffix for new keypairs (case-insensitive)
        #[arg(long, default_value = "ASDF", env = "VANITY_SUFFIX")]
        suffix: String,

        /// Number of threads for generation (default: all cores)
        #[arg(long)]
        threads: Option<usize>,

        /// Minimum pool size before warning
        #[arg(long, default_value_t = 10, env = "VANITY_MIN_POOL")]
        min_pool: usize,

        /// API key for authentication (required in production)
        #[arg(long, env = "VANITY_API_KEY")]
        api_key: Option<String>,

        /// IP whitelist (comma-separated, e.g., "127.0.0.1,10.0.0.1")
        #[arg(long, env = "VANITY_IP_WHITELIST")]
        ip_whitelist: Option<String>,

        /// Rate limit: max requests per minute per IP
        #[arg(long, default_value_t = 60, env = "VANITY_RATE_LIMIT")]
        rate_limit: u32,

        /// Log file path (stdout if not specified)
        #[arg(long, env = "VANITY_LOG_FILE")]
        log_file: Option<String>,

        /// Bind address
        #[arg(long, default_value = "0.0.0.0", env = "VANITY_BIND_ADDR")]
        bind: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VanityMint {
    mint_address: String,
    mint_keypair: String,
    used: bool,
    #[serde(default)]
    attempts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_by_ip: Option<String>,
}

#[derive(Serialize)]
struct PoolStats {
    total: usize,
    available: usize,
    used: usize,
    suffix: String,
    version: String,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct MintResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mint: Option<MintResponseData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    remaining: usize,
}

#[derive(Serialize)]
struct MintResponseData {
    mint_address: String,
    mint_keypair: String,
}

#[derive(Serialize)]
struct RefillResponse {
    success: bool,
    generated: usize,
    total_available: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    pool_available: usize,
    uptime_seconds: u64,
}

// Rate limiter state
struct RateLimiter {
    requests: RwLock<HashMap<IpAddr, Vec<Instant>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(max_requests: u32) -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            max_requests,
            window: Duration::from_secs(60),
        }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut requests = self.requests.write();

        let timestamps = requests.entry(ip).or_insert_with(Vec::new);
        timestamps.retain(|t| now.duration_since(*t) < self.window);

        if timestamps.len() >= self.max_requests as usize {
            return false;
        }

        timestamps.push(now);
        true
    }

    fn cleanup(&self) {
        let now = Instant::now();
        let mut requests = self.requests.write();
        requests.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < self.window);
            !timestamps.is_empty()
        });
    }
}

// Server state
struct ServerState {
    pool: RwLock<Vec<VanityMint>>,
    pool_file: String,
    suffix: String,
    threads: Option<usize>,
    min_pool: usize,
    api_key: Option<String>,
    api_key_hash: Option<String>,
    ip_whitelist: Option<Vec<IpAddr>>,
    rate_limiter: RateLimiter,
    start_time: Instant,
    log_file: Option<RwLock<File>>,
    request_count: AtomicU64,
    shutdown: AtomicBool,
}

impl ServerState {
    fn log(&self, level: &str, message: &str, ip: Option<&str>) {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S%.3f UTC");
        let ip_str = ip.unwrap_or("-");
        let log_line = format!("[{}] [{}] [{}] {}\n", timestamp, level, ip_str, message);

        if let Some(ref log_file) = self.log_file {
            if let Some(mut f) = log_file.try_write() {
                let _ = f.write_all(log_line.as_bytes());
                let _ = f.flush();
            }
        }

        // Always print to stdout
        print!("{}", log_line);
    }

    fn verify_api_key(&self, provided: &str) -> bool {
        match &self.api_key_hash {
            Some(hash) => {
                let mut hasher = Sha256::new();
                hasher.update(provided.as_bytes());
                let provided_hash = hex::encode(hasher.finalize());
                provided_hash == *hash
            }
            None => true, // No API key configured
        }
    }

    fn check_ip_whitelist(&self, ip: IpAddr) -> bool {
        match &self.ip_whitelist {
            Some(whitelist) => whitelist.contains(&ip),
            None => true, // No whitelist configured
        }
    }
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
        .ok();

    let attempts = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let should_stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = bounded::<VanityMint>(count);

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
                    used_at: None,
                    used_by_ip: None,
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

fn get_client_ip(request: &Request) -> Option<IpAddr> {
    // Check X-Forwarded-For header first (for reverse proxy)
    for header in request.headers() {
        let field = header.field.as_str().as_str();
        if field.eq_ignore_ascii_case("X-Forwarded-For") {
            if let Some(first_ip) = header.value.as_str().split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
        if field.eq_ignore_ascii_case("X-Real-IP") {
            if let Ok(ip) = header.value.as_str().trim().parse() {
                return Some(ip);
            }
        }
    }

    // Fall back to remote address
    request.remote_addr().map(|addr| addr.ip())
}

fn get_api_key(request: &Request) -> Option<String> {
    for header in request.headers() {
        let field = header.field.as_str().as_str();
        if field.eq_ignore_ascii_case("X-API-Key") {
            return Some(header.value.as_str().to_string());
        }
        if field.eq_ignore_ascii_case("Authorization") {
            let value = header.value.as_str();
            if value.starts_with("Bearer ") {
                return Some(value[7..].to_string());
            }
        }
    }
    None
}

fn json_response<T: Serialize>(data: &T, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    Response::from_string(body)
        .with_status_code(status)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
        .with_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap())
        .with_header(Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap())
        .with_header(Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).unwrap())
}

fn error_response(message: &str, code: Option<&str>, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let resp = ErrorResponse {
        success: false,
        error: message.to_string(),
        code: code.map(|s| s.to_string()),
    };
    json_response(&resp, status)
}

fn run_generate(suffix: String, count: usize, output: String, threads: Option<usize>, _batch_size: usize) {
    let num_threads = threads.unwrap_or_else(num_cpus::get);

    println!("Solana Vanity Address Generator v{}", VERSION);
    println!("================================");
    println!("Suffix: {} (case-insensitive)", suffix);
    println!("Target count: {}", count);
    println!("Threads: {}", num_threads);
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

fn run_pool_server(
    file: String,
    port: u16,
    suffix: String,
    threads: Option<usize>,
    min_pool: usize,
    api_key: Option<String>,
    ip_whitelist: Option<String>,
    rate_limit: u32,
    log_file: Option<String>,
    bind: String,
) {
    // Parse IP whitelist
    let whitelist: Option<Vec<IpAddr>> = ip_whitelist.map(|s| {
        s.split(',')
            .filter_map(|ip| ip.trim().parse().ok())
            .collect()
    });

    // Hash API key for secure comparison
    let api_key_hash = api_key.as_ref().map(|key| {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    });

    // Open log file if specified
    let log_file_handle = log_file.as_ref().map(|path| {
        RwLock::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("Failed to open log file")
        )
    });

    let state = Arc::new(ServerState {
        pool: RwLock::new(load_pool(&file)),
        pool_file: file.clone(),
        suffix: suffix.clone(),
        threads,
        min_pool,
        api_key: api_key.clone(),
        api_key_hash,
        ip_whitelist: whitelist.clone(),
        rate_limiter: RateLimiter::new(rate_limit),
        start_time: Instant::now(),
        log_file: log_file_handle,
        request_count: AtomicU64::new(0),
        shutdown: AtomicBool::new(false),
    });

    let available = state.pool.read().iter().filter(|m| !m.used).count();

    println!("ASDF Vanity Pool Server v{}", VERSION);
    println!("==============================");
    println!("Pool file: {}", file);
    println!("Suffix: {}", suffix);
    println!("Bind: {}:{}", bind, port);
    println!("Pool size: {} total, {} available", state.pool.read().len(), available);
    println!("Min pool warning: {}", min_pool);
    println!("Rate limit: {} req/min per IP", rate_limit);
    println!("API key: {}", if api_key.is_some() { "ENABLED" } else { "DISABLED (insecure!)" });
    println!("IP whitelist: {}", whitelist.as_ref().map(|w| format!("{} IPs", w.len())).unwrap_or_else(|| "DISABLED".to_string()));
    if let Some(ref path) = log_file {
        println!("Log file: {}", path);
    }
    println!();
    println!("Endpoints:");
    println!("  GET  /health       - Health check (no auth)");
    println!("  GET  /stats        - Pool statistics");
    println!("  GET  /mint         - Get next available mint keypair");
    println!("  POST /refill?count=N - Generate N new keypairs");
    println!();

    if api_key.is_none() {
        println!("⚠️  WARNING: Running without API key authentication!");
        println!("   Set VANITY_API_KEY or --api-key for production use.");
        println!();
    }

    // Setup graceful shutdown
    let shutdown_state = Arc::clone(&state);
    ctrlc::set_handler(move || {
        println!("\n[SHUTDOWN] Received shutdown signal...");
        shutdown_state.shutdown.store(true, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    // Start cleanup thread for rate limiter
    let cleanup_state = Arc::clone(&state);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            if cleanup_state.shutdown.load(Ordering::Relaxed) {
                break;
            }
            cleanup_state.rate_limiter.cleanup();
        }
    });

    let addr = format!("{}:{}", bind, port);
    let server = Server::http(&addr).expect("Failed to start server");

    state.log("INFO", &format!("Server started on http://{}", addr), None);

    for request in server.incoming_requests() {
        if state.shutdown.load(Ordering::Relaxed) {
            state.log("INFO", "Shutting down server", None);
            break;
        }

        let state = Arc::clone(&state);

        // Handle request in thread
        thread::spawn(move || {
            handle_request(request, state);
        });
    }

    // Save pool before exit
    let pool = state.pool.read();
    if let Err(e) = save_pool(&state.pool_file, &pool) {
        eprintln!("[ERROR] Failed to save pool on shutdown: {}", e);
    } else {
        println!("[SHUTDOWN] Pool saved successfully");
    }
}

fn handle_request(request: Request, state: Arc<ServerState>) {
    let method = request.method().clone();
    let path = request.url().split('?').next().unwrap_or("/").to_string();
    let query: HashMap<String, String> = request
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

    let client_ip = get_client_ip(&request);
    let ip_str = client_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string());

    state.request_count.fetch_add(1, Ordering::Relaxed);

    // Log request
    state.log("INFO", &format!("{} {}", method, request.url()), Some(&ip_str));

    // CORS preflight - no auth needed
    if method == Method::Options {
        let response = Response::from_string("")
            .with_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap())
            .with_header(Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap())
            .with_header(Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type, X-API-Key, Authorization"[..]).unwrap())
            .with_header(Header::from_bytes(&b"Access-Control-Max-Age"[..], &b"86400"[..]).unwrap());
        request.respond(response).ok();
        return;
    }

    // Health check - no auth needed
    if path == "/health" && method == Method::Get {
        let available = state.pool.read().iter().filter(|m| !m.used).count();
        let resp = HealthResponse {
            status: "ok".to_string(),
            version: VERSION.to_string(),
            pool_available: available,
            uptime_seconds: state.start_time.elapsed().as_secs(),
        };
        request.respond(json_response(&resp, 200)).ok();
        return;
    }

    // Check IP whitelist
    if let Some(ip) = client_ip {
        if !state.check_ip_whitelist(ip) {
            state.log("WARN", "IP not in whitelist", Some(&ip_str));
            request.respond(error_response("IP not authorized", Some("IP_BLOCKED"), 403)).ok();
            return;
        }
    }

    // Check rate limit
    if let Some(ip) = client_ip {
        if !state.rate_limiter.check(ip) {
            state.log("WARN", "Rate limit exceeded", Some(&ip_str));
            request.respond(error_response("Rate limit exceeded", Some("RATE_LIMITED"), 429)).ok();
            return;
        }
    }

    // Check API key authentication
    if state.api_key.is_some() {
        match get_api_key(&request) {
            Some(key) if state.verify_api_key(&key) => {}
            Some(_) => {
                state.log("WARN", "Invalid API key", Some(&ip_str));
                request.respond(error_response("Invalid API key", Some("INVALID_KEY"), 401)).ok();
                return;
            }
            None => {
                state.log("WARN", "Missing API key", Some(&ip_str));
                request.respond(error_response("API key required", Some("AUTH_REQUIRED"), 401)).ok();
                return;
            }
        }
    }

    // Route to handlers
    let response = match (&method, path.as_str()) {
        (Method::Get, "/stats") => handle_stats(&state),
        (Method::Get, "/mint") => handle_mint(&state, &ip_str),
        (Method::Post, "/refill") => handle_refill(&state, &query),
        _ => error_response("Not found", Some("NOT_FOUND"), 404),
    };

    request.respond(response).ok();
}

fn handle_stats(state: &ServerState) -> Response<std::io::Cursor<Vec<u8>>> {
    let pool = state.pool.read();
    let stats = PoolStats {
        total: pool.len(),
        available: pool.iter().filter(|m| !m.used).count(),
        used: pool.iter().filter(|m| m.used).count(),
        suffix: state.suffix.clone(),
        version: VERSION.to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    };
    json_response(&stats, 200)
}

fn handle_mint(state: &ServerState, ip: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut pool = state.pool.write();

    if let Some(mint) = pool.iter_mut().find(|m| !m.used) {
        mint.used = true;
        mint.used_at = Some(Utc::now().to_rfc3339());
        mint.used_by_ip = Some(ip.to_string());

        let response_data = MintResponseData {
            mint_address: mint.mint_address.clone(),
            mint_keypair: mint.mint_keypair.clone(),
        };

        let remaining = pool.iter().filter(|m| !m.used).count();

        // Save to file
        if let Err(e) = save_pool(&state.pool_file, &pool) {
            state.log("ERROR", &format!("Failed to save pool: {}", e), Some(ip));
        }

        // Warning if low
        if remaining < state.min_pool {
            state.log("WARN", &format!("Pool running low! {} remaining", remaining), None);
        }

        state.log("INFO", &format!("Dispensed mint: {} ({} remaining)", response_data.mint_address, remaining), Some(ip));

        let resp = MintResponse {
            success: true,
            mint: Some(response_data),
            error: None,
            remaining,
        };
        json_response(&resp, 200)
    } else {
        state.log("ERROR", "Pool exhausted", Some(ip));
        let resp = MintResponse {
            success: false,
            mint: None,
            error: Some("No available mints in pool".to_string()),
            remaining: 0,
        };
        json_response(&resp, 503)
    }
}

fn handle_refill(state: &ServerState, query: &HashMap<String, String>) -> Response<std::io::Cursor<Vec<u8>>> {
    let count: usize = query.get("count")
        .and_then(|c| c.parse().ok())
        .unwrap_or(10)
        .min(100); // Max 100 at a time

    state.log("INFO", &format!("Generating {} new keypairs...", count), None);

    let new_mints = generate_keypairs_batch(&state.suffix, count, state.threads, false);

    let mut pool = state.pool.write();
    pool.extend(new_mints);

    if let Err(e) = save_pool(&state.pool_file, &pool) {
        let resp = RefillResponse {
            success: false,
            generated: 0,
            total_available: pool.iter().filter(|m| !m.used).count(),
            error: Some(format!("Failed to save: {}", e)),
        };
        return json_response(&resp, 500);
    }

    let available = pool.iter().filter(|m| !m.used).count();
    state.log("INFO", &format!("Generated {} keypairs. Total available: {}", count, available), None);

    let resp = RefillResponse {
        success: true,
        generated: count,
        total_available: available,
        error: None,
    };
    json_response(&resp, 200)
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Generate { suffix, count, output, threads, batch_size } => {
            run_generate(suffix, count, output, threads, batch_size);
        }
        Commands::Pool { file, port, suffix, threads, min_pool, api_key, ip_whitelist, rate_limit, log_file, bind } => {
            run_pool_server(file, port, suffix, threads, min_pool, api_key, ip_whitelist, rate_limit, log_file, bind);
        }
    }
}
