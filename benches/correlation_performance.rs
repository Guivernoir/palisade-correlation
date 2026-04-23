//! Criterion benchmarks for the public correlation API.

use criterion::{Criterion, criterion_group, criterion_main};
use palisade_config::PolicyConfig;
use palisade_correlation::CorrelationApi;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const SESSIONS: [&str; 8] = [
    "session-a",
    "session-b",
    "session-c",
    "session-d",
    "session-e",
    "session-f",
    "session-g",
    "session-h",
];

fn hardened_policy() -> PolicyConfig {
    let mut policy = PolicyConfig::default();
    CorrelationApi::harden_policy(&mut policy).expect("policy should harden");
    policy
}

fn benchmark_api() -> CorrelationApi<'static> {
    let policy = hardened_policy();
    CorrelationApi::new(&policy).expect("benchmark API should construct")
}

fn bench_construction(c: &mut Criterion) {
    c.bench_function("correlation/new_production", |b| {
        b.iter(|| {
            let mut policy = PolicyConfig::default();
            black_box(
                CorrelationApi::new_production(&mut policy)
                    .expect("production API should construct"),
            );
        });
    });
}

fn bench_observation_hot_paths(c: &mut Criterion) {
    let source_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    let api = benchmark_api();
    let mut index = 0usize;
    c.bench_function("correlation/observe_artifact_access_intrinsic", |b| {
        b.iter(|| {
            let session = SESSIONS[index % SESSIONS.len()];
            index = index.wrapping_add(1);
            api.observe_artifact_access(
                source_ip,
                session,
                "fake-aws-credentials",
                "aws-prod-decoy",
                100.0,
            )
            .expect("artifact access should succeed");
            black_box(api.last_score());
        });
    });

    let api = benchmark_api();
    let mut index = 0usize;
    c.bench_function("correlation/observe_suspicious_process_intrinsic", |b| {
        b.iter(|| {
            let session = SESSIONS[index % SESSIONS.len()];
            index = index.wrapping_add(1);
            api.observe_suspicious_process(source_ip, session, "mimikatz.exe", 1337, 95.0)
                .expect("suspicious process should succeed");
            black_box(api.last_action_code());
        });
    });
}

fn bench_timing_floor(c: &mut Criterion) {
    let source_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    let api = benchmark_api().with_timing_floor(CorrelationApi::DEFAULT_TIMING_FLOOR);
    let mut index = 0usize;

    c.bench_function("correlation/observe_custom_signal_default_floor", |b| {
        b.iter(|| {
            let session = SESSIONS[index % SESSIONS.len()];
            index = index.wrapping_add(1);
            api.observe_custom_signal(source_ip, session, "probe", 50.0)
                .expect("custom signal should succeed");
            black_box(api.last_score());
        });
    });
}

fn bench_result_readback(c: &mut Criterion) {
    let api = benchmark_api();
    let source_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));

    api.observe_artifact_access(
        source_ip,
        "session-readback",
        "fake-aws-credentials",
        "aws-prod-decoy",
        100.0,
    )
    .expect("seed event should succeed");
    api.observe_suspicious_process(source_ip, "session-readback", "mimikatz.exe", 7331, 95.0)
        .expect("seed process event should succeed");

    let mut patterns = [0u16; CorrelationApi::MAX_PATTERN_CODES];
    let mut source = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];

    c.bench_function("correlation/result_readback", |b| {
        b.iter(|| {
            let pattern_count = api.write_last_pattern_codes(&mut patterns);
            let source_written = api.write_last_source_ip(&mut source);
            black_box((pattern_count, source_written, &patterns, &source));
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets =
        bench_construction,
        bench_observation_hot_paths,
        bench_timing_floor,
        bench_result_readback
}
criterion_main!(benches);
