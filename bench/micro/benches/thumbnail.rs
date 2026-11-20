//! Thumbnail of a full-HD screenshot (PNG decode, resize, JPEG encode).

use criterion::{Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use cursor_clip::backend::backend_state::scale_image;
use cursor_clip_bench::{PixelFormat, SCREENSHOT_SIZE, screenshot_png};
use std::hint::black_box;
use std::time::Duration;

fn thumbnail(c: &mut Criterion) {
    let mut group = c.benchmark_group("thumbnail/scale_image");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(40)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8));

    for format in [PixelFormat::Rgb8, PixelFormat::Rgba8] {
        let png = screenshot_png(42, SCREENSHOT_SIZE, format);
        let (width, height) = SCREENSHOT_SIZE;
        let name = format!("{width}x{height}_{}", format.name());
        let thumbnail = scale_image(&png).expect("screenshot can be thumbnailed");
        eprintln!(
            "fixture {name}: PNG {} bytes, thumbnail {} bytes",
            png.len(),
            thumbnail.len()
        );

        group.throughput(Throughput::Bytes(png.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| black_box(scale_image(black_box(&png)).expect("thumbnail")));
        });
    }
    group.finish();
}

criterion_group!(benches, thumbnail);
criterion_main!(benches);
