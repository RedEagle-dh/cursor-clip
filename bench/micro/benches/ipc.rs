//! The `History` reply the daemon sends whenever the overlay opens.

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use cursor_clip::shared::BackendMessage;
use cursor_clip_bench::{HistoryMix, history_previews};
use std::hint::black_box;
use std::time::Duration;

fn history_reply(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/history");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(60)
        .measurement_time(Duration::from_secs(8));

    for mix in [HistoryMix::MostlyText, HistoryMix::AllImages] {
        let message = BackendMessage::History {
            items: history_previews(mix),
        };
        // Same calls as the daemon (`to_vec`) and the overlay (`from_slice`).
        let encoded = serde_json::to_vec(&message).expect("encode history");
        eprintln!(
            "fixture ipc/history/{}: encoded reply {} bytes",
            mix.name(),
            encoded.len()
        );

        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_function(BenchmarkId::new("encode", mix.name()), |b| {
            b.iter(|| serde_json::to_vec(black_box(&message)).expect("encode"));
        });
        group.bench_function(BenchmarkId::new("decode", mix.name()), |b| {
            b.iter(|| {
                serde_json::from_slice::<BackendMessage>(black_box(&encoded)).expect("decode")
            });
        });
    }
    group.finish();
}

criterion_group!(benches, history_reply);
criterion_main!(benches);
