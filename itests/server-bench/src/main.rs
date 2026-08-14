#![allow(missing_docs)]

use std::{
    alloc::System,
    env,
    error::Error,
    fs,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bondry_core::{
    AdapterId, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError, DenialReason,
    DispatchError, DispatchFuture, Invocation, Principal, PrincipalId, PrincipalKind,
};
#[cfg(bondry_legacy_layout)]
use bondry_http::{Authentication, HttpAdapter, LocalHttpServer, RateLimits, ServerConfiguration};
#[cfg(not(bondry_legacy_layout))]
use bondry_http_server::{
    Authentication, LocalHttpServer, MountedProtocol, RateLimits, ServerConfiguration,
};
#[cfg(bondry_legacy_layout)]
use bondry_mcp::{McpAdapter, McpServerInfo};
#[cfg(not(bondry_legacy_layout))]
use bondry_mcp_proto::{McpAdapter, McpServerInfo};
#[cfg(bondry_legacy_layout)]
use bondry_rest::RestAdapter;
#[cfg(not(bondry_legacy_layout))]
use bondry_rest_proto::RestAdapter;
use serde::Serialize;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static ALLOCATOR: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const DEFAULT_WARMUP_REQUESTS: usize = 5_000;
const DEFAULT_MEASURED_REQUESTS: usize = 50_000;
const DEFAULT_CONNECTIONS: usize = 8;
const SAMPLE_INTERVAL: Duration = Duration::from_millis(25);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("serve") => serve(),
        Some("run") => run_driver(Options::parse(arguments)?),
        _ => Err("usage: bondry-server-bench <run|serve>".into()),
    }
}

#[derive(Clone)]
struct Options {
    revision: String,
    profile: String,
    target: String,
    warmup_requests: usize,
    measured_requests: usize,
    connections: usize,
}

impl Options {
    fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut options = Self {
            revision: "unknown".to_owned(),
            profile: "unknown".to_owned(),
            target: format!("{}-{}", env::consts::ARCH, env::consts::OS),
            warmup_requests: DEFAULT_WARMUP_REQUESTS,
            measured_requests: DEFAULT_MEASURED_REQUESTS,
            connections: DEFAULT_CONNECTIONS,
        };
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| format!("{argument} requires a value"))?;
            match argument.as_str() {
                "--revision" => options.revision = value,
                "--profile" => options.profile = value,
                "--target" => options.target = value,
                "--warmup" => options.warmup_requests = positive(&value, "--warmup")?,
                "--requests" => options.measured_requests = positive(&value, "--requests")?,
                "--connections" => options.connections = positive(&value, "--connections")?,
                _ => return Err(format!("unknown option: {argument}").into()),
            }
        }
        if options.warmup_requests + options.measured_requests > 60_000 {
            return Err("warmup plus measured requests must not exceed 60,000".into());
        }
        Ok(options)
    }
}

fn positive(value: &str, option: &str) -> Result<usize, Box<dyn Error>> {
    let parsed = value.parse::<usize>()?;
    if parsed == 0 {
        return Err(format!("{option} must be positive").into());
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Rest,
    Mcp,
}

impl Protocol {
    const ALL: [Self; 2] = [Self::Rest, Self::Mcp];

    fn request(self) -> Vec<u8> {
        match self {
            Self::Rest => b"GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".to_vec(),
            Self::Mcp => {
                let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
                format!(
                    "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2025-11-25\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(body)
                )
                .into_bytes()
            }
        }
    }
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    revision: String,
    profile: String,
    target: String,
    rustc: String,
    binary_bytes: u64,
    warmup_requests: usize,
    measured_requests: usize,
    connections: usize,
    protocols: Vec<ProtocolReport>,
}

#[derive(Serialize)]
struct ProtocolReport {
    protocol: Protocol,
    latency_ns_p50: u64,
    latency_ns_p95: u64,
    latency_ns_p99: u64,
    throughput_requests_per_second: f64,
    rss_baseline_bytes: u64,
    rss_peak_bytes: u64,
    rss_peak_delta_bytes: u64,
    allocations: usize,
    deallocations: usize,
    reallocations: usize,
    bytes_allocated: usize,
    bytes_deallocated: usize,
    bytes_reallocated: isize,
    allocations_per_request: f64,
    allocated_bytes_per_request: f64,
}

fn run_driver(options: Options) -> Result<(), Box<dyn Error>> {
    let executable = env::current_exe()?;
    let binary_bytes = fs::metadata(&executable)?.len();
    let rustc = command_output("rustc", &["-V"])?;
    let mut protocols = Vec::with_capacity(Protocol::ALL.len());
    for protocol in Protocol::ALL {
        protocols.push(measure_protocol(&executable, &options, protocol)?);
    }
    let report = Report {
        schema_version: 1,
        revision: options.revision,
        profile: options.profile,
        target: options.target,
        rustc,
        binary_bytes,
        warmup_requests: options.warmup_requests,
        measured_requests: options.measured_requests,
        connections: options.connections,
        protocols,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn measure_protocol(
    executable: &PathBuf,
    options: &Options,
    protocol: Protocol,
) -> Result<ProtocolReport, Box<dyn Error>> {
    let mut server = ServerProcess::start(executable)?;
    run_load(
        server.address,
        protocol.request(),
        options.warmup_requests,
        options.connections,
    )?;
    let rss_baseline = resident_bytes(server.id())?;
    server.reset_allocations()?;

    let sampling = Arc::new(AtomicBool::new(true));
    let sampler_flag = Arc::clone(&sampling);
    let process_id = server.id();
    let sampler = thread::spawn(move || sample_peak_rss(process_id, rss_baseline, &sampler_flag));
    let load = run_load(
        server.address,
        protocol.request(),
        options.measured_requests,
        options.connections,
    )?;
    sampling.store(false, Ordering::Release);
    let rss_peak = sampler
        .join()
        .map_err(|_| "RSS sampler thread panicked")?
        .max(resident_bytes(server.id())?);
    let allocations = server.allocation_snapshot()?;
    server.stop()?;

    let requests = options.measured_requests as f64;
    Ok(ProtocolReport {
        protocol,
        latency_ns_p50: percentile(&load.latencies, 50),
        latency_ns_p95: percentile(&load.latencies, 95),
        latency_ns_p99: percentile(&load.latencies, 99),
        throughput_requests_per_second: requests / load.elapsed.as_secs_f64(),
        rss_baseline_bytes: rss_baseline,
        rss_peak_bytes: rss_peak,
        rss_peak_delta_bytes: rss_peak.saturating_sub(rss_baseline),
        allocations: allocations.allocations,
        deallocations: allocations.deallocations,
        reallocations: allocations.reallocations,
        bytes_allocated: allocations.bytes_allocated,
        bytes_deallocated: allocations.bytes_deallocated,
        bytes_reallocated: allocations.bytes_reallocated,
        allocations_per_request: allocations.allocations as f64 / requests,
        allocated_bytes_per_request: allocations.bytes_allocated as f64 / requests,
    })
}

struct LoadResult {
    latencies: Vec<u64>,
    elapsed: Duration,
}

fn run_load(
    address: SocketAddr,
    request: Vec<u8>,
    request_count: usize,
    connections: usize,
) -> Result<LoadResult, Box<dyn Error>> {
    let ready = Arc::new(Barrier::new(connections + 1));
    let start = Arc::new(Barrier::new(connections + 1));
    let request = Arc::new(request);
    let mut workers = Vec::with_capacity(connections);
    for worker in 0..connections {
        let ready = Arc::clone(&ready);
        let start = Arc::clone(&start);
        let request = Arc::clone(&request);
        let count = request_count / connections + usize::from(worker < request_count % connections);
        workers.push(thread::spawn(move || -> Result<Vec<u64>, String> {
            let mut client = HttpClient::connect(address).map_err(|error| error.to_string())?;
            let mut latencies = Vec::with_capacity(count);
            ready.wait();
            start.wait();
            for _ in 0..count {
                let started = Instant::now();
                client
                    .round_trip(&request)
                    .map_err(|error| error.to_string())?;
                latencies.push(duration_ns(started.elapsed()));
            }
            Ok(latencies)
        }));
    }
    ready.wait();
    let started = Instant::now();
    start.wait();
    let mut latencies = Vec::with_capacity(request_count);
    for worker in workers {
        let worker_latencies = worker
            .join()
            .map_err(|_| "load worker thread panicked")?
            .map_err(|error| format!("load worker failed: {error}"))?;
        latencies.extend(worker_latencies);
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    Ok(LoadResult { latencies, elapsed })
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let index = (sorted.len() - 1) * percentile / 100;
    sorted[index]
}

struct HttpClient {
    stream: BufReader<TcpStream>,
    line: String,
    body: Vec<u8>,
}

impl HttpClient {
    fn connect(address: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(address)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self {
            stream: BufReader::new(stream),
            line: String::with_capacity(256),
            body: Vec::new(),
        })
    }

    fn round_trip(&mut self, request: &[u8]) -> io::Result<()> {
        self.stream.get_mut().write_all(request)?;
        let mut content_length = None;
        self.line.clear();
        self.stream.read_line(&mut self.line)?;
        if !self.line.starts_with("HTTP/1.1 200 ") {
            return Err(io::Error::other(format!(
                "unexpected response status: {}",
                self.line.trim()
            )));
        }
        loop {
            self.line.clear();
            self.stream.read_line(&mut self.line)?;
            if self.line == "\r\n" {
                break;
            }
            if let Some((name, value)) = self.line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| io::Error::other("invalid content length"))?,
                );
            }
        }
        let content_length =
            content_length.ok_or_else(|| io::Error::other("missing content length"))?;
        self.body.resize(content_length, 0);
        self.stream.read_exact(&mut self.body)
    }
}

struct ServerProcess {
    child: Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
    address: SocketAddr,
}

impl ServerProcess {
    fn start(executable: &PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new(executable)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = BufWriter::new(child.stdin.take().ok_or("server stdin was not piped")?);
        let mut output = BufReader::new(child.stdout.take().ok_or("server stdout was not piped")?);
        let ready = read_control_line(&mut output)?;
        let address = ready
            .strip_prefix("READY ")
            .ok_or("server did not report readiness")?
            .parse()?;
        Ok(Self {
            child,
            input,
            output,
            address,
        })
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn reset_allocations(&mut self) -> Result<(), Box<dyn Error>> {
        self.command("reset")?;
        if read_control_line(&mut self.output)? != "RESET" {
            return Err("server did not reset allocation statistics".into());
        }
        Ok(())
    }

    fn allocation_snapshot(&mut self) -> Result<Stats, Box<dyn Error>> {
        self.command("snapshot")?;
        parse_stats(&read_control_line(&mut self.output)?)
    }

    fn stop(mut self) -> Result<(), Box<dyn Error>> {
        self.command("stop")?;
        if read_control_line(&mut self.output)? != "STOPPED" {
            return Err("server did not acknowledge shutdown".into());
        }
        let status = self.child.wait()?;
        if !status.success() {
            return Err(format!("server exited with {status}").into());
        }
        Ok(())
    }

    fn command(&mut self, command: &str) -> io::Result<()> {
        writeln!(self.input, "{command}")?;
        self.input.flush()
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_control_line(output: &mut BufReader<ChildStdout>) -> io::Result<String> {
    let mut line = String::new();
    if output.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "server control channel closed",
        ));
    }
    Ok(line.trim().to_owned())
}

fn parse_stats(line: &str) -> Result<Stats, Box<dyn Error>> {
    let values = line
        .strip_prefix("ALLOC ")
        .ok_or("server did not report allocation statistics")?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if values.len() != 6 {
        return Err("invalid allocation statistics".into());
    }
    Ok(Stats {
        allocations: values[0].parse()?,
        deallocations: values[1].parse()?,
        reallocations: values[2].parse()?,
        bytes_allocated: values[3].parse()?,
        bytes_deallocated: values[4].parse()?,
        bytes_reallocated: values[5].parse()?,
    })
}

fn sample_peak_rss(process_id: u32, initial: u64, running: &AtomicBool) -> u64 {
    let mut peak = initial;
    while running.load(Ordering::Acquire) {
        if let Ok(rss) = resident_bytes(process_id) {
            peak = peak.max(rss);
        }
        thread::sleep(SAMPLE_INTERVAL);
    }
    peak
}

fn resident_bytes(process_id: u32) -> Result<u64, Box<dyn Error>> {
    let process = process_id.to_string();
    let kibibytes = command_output("ps", &["-o", "rss=", "-p", &process])?
        .trim()
        .parse::<u64>()?;
    Ok(kibibytes * 1_024)
}

fn command_output(command: &str, arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new(command).args(arguments).output()?;
    if !output.status.success() {
        return Err(format!("{command} exited with {}", output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct EmptyService;

impl AutomationService for EmptyService {
    fn capabilities(
        &self,
        _principal: &Principal,
        _adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        Ok(Vec::new())
    }

    fn dispatch(&self, _invocation: Invocation) -> DispatchFuture<'_> {
        Box::pin(async { Err(DispatchError::AccessDenied(DenialReason::NotGranted)) })
    }
}

fn serve() -> Result<(), Box<dyn Error>> {
    let principal = Principal::new(
        PrincipalId::new("phase_zero_benchmark")?,
        PrincipalKind::Application,
    );
    let service: Arc<dyn AutomationService> = Arc::new(EmptyService);
    let mut server = start_server(principal, service)?;
    println!("READY {}", server.local_address());
    io::stdout().flush()?;

    let mut region = Region::new(ALLOCATOR);
    let mut line = String::with_capacity(16);
    loop {
        line.clear();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        match line.trim() {
            "reset" => {
                region = Region::new(ALLOCATOR);
                println!("RESET");
            }
            "snapshot" => {
                let stats = region.change();
                println!(
                    "ALLOC {} {} {} {} {} {}",
                    stats.allocations,
                    stats.deallocations,
                    stats.reallocations,
                    stats.bytes_allocated,
                    stats.bytes_deallocated,
                    stats.bytes_reallocated
                );
            }
            "stop" => break,
            command => return Err(format!("unknown server command: {command}").into()),
        }
        io::stdout().flush()?;
    }
    server.stop()?;
    println!("STOPPED");
    io::stdout().flush()?;
    Ok(())
}

#[cfg(not(bondry_legacy_layout))]
fn start_server(
    principal: Principal,
    service: Arc<dyn AutomationService>,
) -> Result<LocalHttpServer, Box<dyn Error>> {
    let rest = RestAdapter::new(Arc::clone(&service))?;
    let mcp = McpAdapter::new(service, McpServerInfo::new("phase-zero", "0.1.2")?)?;
    let configuration = ServerConfiguration::new(Authentication::disabled(principal))
        .with_rate_limits(RateLimits::new(60_000, 60_000)?);
    Ok(LocalHttpServer::start(
        configuration,
        vec![MountedProtocol::Rest(rest), MountedProtocol::Mcp(mcp)],
    )?)
}

#[cfg(bondry_legacy_layout)]
fn start_server(
    principal: Principal,
    service: Arc<dyn AutomationService>,
) -> Result<LocalHttpServer, Box<dyn Error>> {
    let adapters: Vec<Arc<dyn HttpAdapter>> = vec![
        Arc::new(RestAdapter::new(Arc::clone(&service))?),
        Arc::new(McpAdapter::new(
            service,
            McpServerInfo::new("phase-zero", "0.1.2")?,
        )?),
    ];
    let configuration = ServerConfiguration::new(Authentication::disabled(principal))
        .with_rate_limits(RateLimits::new(60_000, 60_000)?);
    Ok(LocalHttpServer::start(configuration, adapters)?)
}
