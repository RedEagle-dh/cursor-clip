//! History changes on a full history: adding a copy and pinning an entry.

use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use cursor_clip::shared::ClipboardContentType;
use cursor_clip_bench::{
    HISTORY_LEN, HistoryMix, PixelFormat, SCREENSHOT_SIZE, StateFixture, StoreKind, image_copy,
    plain_text_copy, rich_text_copy, sample_html, screenshot_png,
};
use indexmap::IndexMap;
use std::hint::black_box;
use std::time::Duration;

/// Kind of copy added to the history.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyKind {
    PlainText,
    RichText,
    ScreenshotRgba,
}

impl CopyKind {
    const ALL: [Self; 3] = [Self::PlainText, Self::RichText, Self::ScreenshotRgba];

    const fn name(self) -> &'static str {
        match self {
            Self::PlainText => "plain_text",
            Self::RichText => "rich_text",
            Self::ScreenshotRgba => "screenshot_rgba",
        }
    }
}

/// Number of distinct screenshots the screenshot copies cycle through.
///
/// The history keeps `HISTORY_LEN / 5` = 20 images, so a screenshot has been
/// evicted, and its blobs deleted, before it is copied again: like real
/// screenshots, every copy has new pixels and writes a new payload and a new
/// thumbnail (see [`assert_screenshots_write_new_blobs`]).
const SCREENSHOT_POOL_LEN: u64 = 24;

/// Full-HD RGBA screenshots with distinct pixels.
fn screenshot_pool() -> Vec<Bytes> {
    (0..SCREENSHOT_POOL_LEN)
        .map(|index| {
            Bytes::from(screenshot_png(
                42 + index,
                SCREENSHOT_SIZE,
                PixelFormat::Rgba8,
            ))
        })
        .collect()
}

/// Builds a new, unique copy of one kind for every iteration.
struct CopySource {
    kind: CopyKind,
    text: String,
    html: String,
    /// Cycled by screenshot copies; empty for other kinds.
    screenshots: Vec<Bytes>,
    copies: u64,
}

impl CopySource {
    fn new(kind: CopyKind, screenshots: &[Bytes]) -> Self {
        // About 2.5 KiB of text, a typical paragraph or code snippet.
        let text = "Clipboard history keeps every copy available from the overlay. ".repeat(40);
        let html = sample_html(&text);
        let screenshots = if kind == CopyKind::ScreenshotRgba {
            screenshots.to_vec()
        } else {
            Vec::new()
        };
        Self {
            kind,
            text,
            html,
            screenshots,
            copies: 0,
        }
    }

    fn next(&mut self) -> IndexMap<String, Bytes> {
        self.copies += 1;
        let n = self.copies;
        match self.kind {
            CopyKind::PlainText => plain_text_copy(&format!("[{n}] {}", self.text)),
            CopyKind::RichText => rich_text_copy(
                &format!("[{n}] {}", self.text),
                &format!("<!-- {n} -->{}", self.html),
            ),
            CopyKind::ScreenshotRgba => {
                image_copy(self.screenshots[(n % SCREENSHOT_POOL_LEN) as usize].clone())
            }
        }
    }
}

/// A full history in which adding copies of `copy` keeps the composition stable.
fn history_for(copy: CopyKind, store_kind: StoreKind) -> StateFixture {
    let mut fixture = StateFixture::prefilled(store_kind, HistoryMix::MostlyText);
    // Pin the entries of the other kind so the history keeps 20 images
    // and 80 texts while the same kind of copy is added again and again.
    let adding_images = copy == CopyKind::ScreenshotRgba;
    fixture
        .pin_matching(|item| (item.content_type == ClipboardContentType::Image) != adding_images);
    fixture
}

/// Add two rounds of the screenshot pool and check that every copy writes
/// new blob files: its payload and, in a persistent store, its thumbnail.
/// The second round re-adds screenshots that were copied before.
fn assert_screenshots_write_new_blobs(
    fixture: &mut StateFixture,
    source: &mut CopySource,
    store_kind: StoreKind,
) {
    let expected = match store_kind {
        StoreKind::Ephemeral => 1,
        StoreKind::Persistent => 2,
    };
    for _ in 0..2 * SCREENSHOT_POOL_LEN {
        let before = fixture.blob_names();
        fixture
            .state
            .add_clipboard_item_from_mime_map(source.next())
            .expect("copy is added");
        let written = fixture.blob_names().difference(&before).count();
        assert_eq!(written, expected, "new blob files for one screenshot copy");
    }
}

fn add_item(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/add_item");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(30)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8));

    let screenshots = screenshot_pool();
    for copy in CopyKind::ALL {
        for store_kind in StoreKind::ALL {
            let mut fixture = history_for(copy, store_kind);
            let mut source = CopySource::new(copy, &screenshots);
            if copy == CopyKind::ScreenshotRgba {
                assert_screenshots_write_new_blobs(&mut fixture, &mut source, store_kind);
            }

            group.bench_function(BenchmarkId::new(copy.name(), store_kind.name()), |b| {
                b.iter_batched(
                    || source.next(),
                    |mimes| {
                        black_box(
                            fixture
                                .state
                                .add_clipboard_item_from_mime_map(mimes)
                                .expect("copy is added"),
                        )
                    },
                    BatchSize::PerIteration,
                );
            });
            assert_eq!(fixture.state.history.len(), HISTORY_LEN);
            assert_eq!(fixture.image_count(), HISTORY_LEN / 5);
        }
    }
    group.finish();
}

fn set_pinned(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/set_pinned");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(30)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8));

    for (store_kind, mix) in [
        (StoreKind::Persistent, HistoryMix::MostlyText),
        (StoreKind::Persistent, HistoryMix::AllImages),
        (StoreKind::Ephemeral, HistoryMix::MostlyText),
    ] {
        let mut fixture = StateFixture::prefilled(store_kind, mix);
        let id = fixture.state.history[HISTORY_LEN / 2].item_id;

        // One iteration is a pin followed by an unpin: two history changes.
        group.bench_function(BenchmarkId::new(store_kind.name(), mix.name()), |b| {
            b.iter(|| {
                fixture.state.set_pinned(black_box(id), true).expect("pin");
                fixture
                    .state
                    .set_pinned(black_box(id), false)
                    .expect("unpin");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, add_item, set_pinned);
criterion_main!(benches);
