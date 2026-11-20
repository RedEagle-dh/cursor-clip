//! Encrypted blob store: write a new payload and read one back.

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use cursor_clip_bench::{BenchDir, StoreKind, random_bytes};
use std::hint::black_box;
use std::time::{Duration, Instant};

const SIZES: [(&str, usize); 2] = [("4KiB", 4 * 1024), ("2MiB", 2 * 1024 * 1024)];

/// Unreferenced blobs are deleted after this many writes (outside the timed
/// region) so the blob directory and disk usage stay small.
const COLLECT_EVERY: u64 = 32;

fn put_blob(c: &mut Criterion) {
    let mut group = c.benchmark_group("store/put_blob");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(40)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(6));

    for store_kind in StoreKind::ALL {
        for (label, size) in SIZES {
            let dir = BenchDir::new("put-blob");
            let store = store_kind.open(dir.path());
            let mut payload = random_bytes(size as u64, size);
            let mut written = 0u64;

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new(store_kind.name(), label), |b| {
                b.iter_custom(|iters| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        // A unique prefix defeats content addressing: every write is a new blob.
                        written += 1;
                        payload[..8].copy_from_slice(&written.to_le_bytes());
                        let start = Instant::now();
                        black_box(store.put_blob(black_box(&payload)).expect("store blob"));
                        elapsed += start.elapsed();
                        if written.is_multiple_of(COLLECT_EVERY) {
                            store.collect_garbage(&[]);
                        }
                    }
                    elapsed
                });
            });
            drop(store);
            drop(dir);
        }
    }
    group.finish();
}

fn get_blob(c: &mut Criterion) {
    let mut group = c.benchmark_group("store/get_blob");
    group
        .sample_size(50)
        .measurement_time(Duration::from_secs(8));
    let (label, size) = SIZES[1];
    let dir = BenchDir::new("get-blob");
    let store = StoreKind::Ephemeral.open(dir.path());
    let id = store.put_blob(&random_bytes(7, size)).expect("store blob");

    group.throughput(Throughput::Bytes(size as u64));
    group.bench_function(label, |b| {
        b.iter(|| black_box(store.get_blob(black_box(&id)).expect("read blob")));
    });
    group.finish();
}

// `get_blob` runs first so its result does not depend on the large allocations
// `put_blob` leaves behind (glibc adapts its mmap threshold to freed buffers).
criterion_group!(benches, get_blob, put_blob);
criterion_main!(benches);
