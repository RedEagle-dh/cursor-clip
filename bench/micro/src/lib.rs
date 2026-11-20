//! Deterministic fixtures shared by the cursor-clip micro benchmarks.
//!
//! Every fixture is generated from a fixed seed, so repeated runs measure the
//! same data. Store directories are created below [`std::env::temp_dir`]
//! (honours `TMPDIR`) and removed again when the owning fixture is dropped.

use bytes::Bytes;
use cursor_clip::backend::backend_state::BackendState;
use cursor_clip::backend::store::ClipboardStore;
use cursor_clip::shared::{ClipboardContentType, ClipboardItem, ClipboardItemPreview};
use image::{DynamicImage, ImageFormat, RgbImage, RgbaImage};
use indexmap::IndexMap;
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of entries the daemon keeps in its history.
pub const HISTORY_LEN: usize = 100;

/// MIME types a toolkit offers for a plain text copy, all with the same bytes.
pub const TEXT_MIMES: [&str; 5] = [
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "TEXT",
    "STRING",
];

/// Size of a full-HD screenshot.
pub const SCREENSHOT_SIZE: (u32, u32) = (1920, 1080);

/// Smaller screenshots used to prefill histories quickly.
const PREFILL_IMAGE_SIZE: (u32, u32) = (640, 360);

/// Small, fast and deterministic pseudo random generator (SplitMix64).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

/// Incompressible bytes of the given length.
pub fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    Rng::new(seed).fill(&mut bytes);
    bytes
}

/// Pixel layout of a generated screenshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Rgb8,
    /// RGBA with every pixel fully opaque, as most screenshot tools produce.
    Rgba8,
}

impl PixelFormat {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rgb8 => "rgb8",
            Self::Rgba8 => "rgba8",
        }
    }
}

/// Screenshot-like PNG: bands of flat UI colour alternating with noisy
/// content (every third 40 pixel band), like `make_png` in
/// `bench/clipboard_bench.py`.
pub fn screenshot_png(seed: u64, (width, height): (u32, u32), format: PixelFormat) -> Vec<u8> {
    let channels = match format {
        PixelFormat::Rgb8 => 3,
        PixelFormat::Rgba8 => 4,
    };
    let mut rng = Rng::new(seed);
    let mut pixels = Vec::with_capacity(width as usize * height as usize * channels);
    for y in 0..u64::from(height) {
        let noisy = (y / 40) % 3 == 0;
        let flat = [
            ((y + seed * 17) % 256) as u8,
            ((seed * 31) % 256) as u8,
            200,
        ];
        for _ in 0..width {
            let rgb = if noisy {
                let [r, g, b, ..] = rng.next_u64().to_le_bytes();
                [r, g, b]
            } else {
                flat
            };
            pixels.extend_from_slice(&rgb);
            if format == PixelFormat::Rgba8 {
                pixels.push(u8::MAX);
            }
        }
    }

    let image = match format {
        PixelFormat::Rgb8 => DynamicImage::ImageRgb8(
            RgbImage::from_raw(width, height, pixels).expect("pixel buffer matches dimensions"),
        ),
        PixelFormat::Rgba8 => DynamicImage::ImageRgba8(
            RgbaImage::from_raw(width, height, pixels).expect("pixel buffer matches dimensions"),
        ),
    };
    let mut png = Cursor::new(Vec::new());
    image
        .write_to(&mut png, ImageFormat::Png)
        .expect("encoding a generated PNG cannot fail");
    png.into_inner()
}

/// Text of a few to a few hundred words, like `make_text` in `bench/clipboard_bench.py`.
pub fn sample_text(seed: u64) -> String {
    const WORDS: [&str; 11] = [
        "clipboard",
        "history",
        "wayland",
        "overlay",
        "rust",
        "gtk",
        "layer",
        "shell",
        "daemon",
        "paste",
        "copy",
    ];
    const LENGTHS: [usize; 5] = [3, 12, 40, 150, 400];
    let mut rng = Rng::new(seed);
    let length = LENGTHS[rng.below(LENGTHS.len())];
    let words: Vec<&str> = (0..length).map(|_| WORDS[rng.below(WORDS.len())]).collect();
    format!("[{seed}] {}", words.join(" "))
}

/// HTML a browser offers next to the plain text of the same selection.
pub fn sample_html(text: &str) -> String {
    let paragraphs: String = text
        .split_inclusive(". ")
        .map(|sentence| format!("<p style=\"margin: 0 0 8px 0\"><span>{sentence}</span></p>"))
        .collect();
    format!(
        "<meta charset=\"utf-8\"><div style=\"font-family: sans-serif; font-size: 14px\">{paragraphs}</div>"
    )
}

/// The same text offered under every common text MIME type.
pub fn plain_text_copy(text: &str) -> IndexMap<String, Bytes> {
    let bytes = Bytes::copy_from_slice(text.as_bytes());
    TEXT_MIMES
        .iter()
        .map(|mime| ((*mime).to_owned(), bytes.clone()))
        .collect()
}

/// A plain text copy plus a distinct `text/html` representation.
pub fn rich_text_copy(text: &str, html: &str) -> IndexMap<String, Bytes> {
    let mut mimes = plain_text_copy(text);
    mimes.insert(
        "text/html".to_owned(),
        Bytes::copy_from_slice(html.as_bytes()),
    );
    mimes
}

/// A screenshot copy offering only `image/png`.
pub fn image_copy(png: impl Into<Bytes>) -> IndexMap<String, Bytes> {
    IndexMap::from([("image/png".to_owned(), png.into())])
}

/// Directory removed with everything in it when dropped.
#[derive(Debug)]
pub struct BenchDir(PathBuf);

impl BenchDir {
    pub fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cursor-clip-bench-{}-{label}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&path).expect("create benchmark directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for BenchDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove {}: {e}", self.0.display());
        }
    }
}

/// Which kind of clipboard store backs a benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// Session-only history: payloads on disk, no index.
    Ephemeral,
    /// Persistent history: payloads plus an index rewritten on every change.
    Persistent,
}

impl StoreKind {
    pub const ALL: [Self; 2] = [Self::Ephemeral, Self::Persistent];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Persistent => "persistent",
        }
    }

    pub fn open(self, dir: &Path) -> ClipboardStore {
        let dir = store_dir(dir);
        match self {
            Self::Ephemeral => ClipboardStore::open_ephemeral_at(dir),
            Self::Persistent => ClipboardStore::open_persistent_at(dir, "benchmark password"),
        }
        .expect("open benchmark store")
    }
}

/// Directory of the store of a fixture living in `dir`.
fn store_dir(dir: &Path) -> PathBuf {
    dir.join("store")
}

/// Composition of a prefilled history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMix {
    /// Every fifth entry is a screenshot with a thumbnail, the rest is text.
    MostlyText,
    /// Every entry is a screenshot with a thumbnail.
    AllImages,
}

impl HistoryMix {
    pub const fn name(self) -> &'static str {
        match self {
            Self::MostlyText => "20_images",
            Self::AllImages => "100_images",
        }
    }

    const fn is_image(self, index: usize) -> bool {
        match self {
            Self::MostlyText => index.is_multiple_of(5),
            Self::AllImages => true,
        }
    }
}

/// A backend state with a full history, stored in its own directory.
#[derive(Debug)]
pub struct StateFixture {
    // Declared before `dir` so the store is dropped before its directory is removed.
    pub state: BackendState,
    dir: BenchDir,
}

impl StateFixture {
    /// Fill a new state with [`HISTORY_LEN`] unique entries through the real
    /// ingest path, so images get real thumbnails.
    pub fn prefilled(store: StoreKind, mix: HistoryMix) -> Self {
        let dir = BenchDir::new(store.name());
        let mut state = BackendState::with_store(false, store.open(dir.path()));
        for index in 0..HISTORY_LEN {
            let seed = index as u64 + 1;
            let mimes = if mix.is_image(index) {
                image_copy(screenshot_png(seed, PREFILL_IMAGE_SIZE, PixelFormat::Rgb8))
            } else {
                plain_text_copy(&sample_text(seed))
            };
            state
                .add_clipboard_item_from_mime_map(mimes)
                .expect("prefill entry is stored");
        }
        assert_eq!(state.history.len(), HISTORY_LEN);
        assert_eq!(
            state
                .history
                .iter()
                .filter(|item| item.thumbnail.is_some())
                .count(),
            (0..HISTORY_LEN).filter(|&i| mix.is_image(i)).count(),
            "every prefilled image has a thumbnail"
        );
        Self { state, dir }
    }

    /// Pin every entry matching `predicate`.
    ///
    /// New entries evict the oldest unpinned one, so pinning the entries of
    /// the other kind keeps the history composition stable while one kind of
    /// content is added over and over.
    pub fn pin_matching(&mut self, predicate: impl Fn(&ClipboardItem) -> bool) {
        let ids: Vec<u64> = self
            .state
            .history
            .iter()
            .filter(|item| predicate(item))
            .map(|item| item.item_id)
            .collect();
        for id in ids {
            self.state.set_pinned(id, true).expect("entry exists");
        }
    }

    /// Names of the blob files currently in the store directory
    /// (`blobs/` in the store's layout).
    pub fn blob_names(&self) -> HashSet<OsString> {
        std::fs::read_dir(store_dir(self.dir.path()).join("blobs"))
            .expect("read blob directory")
            .map(|entry| entry.expect("read blob directory entry").file_name())
            .collect()
    }

    pub fn image_count(&self) -> usize {
        self.state
            .history
            .iter()
            .filter(|item| item.content_type == ClipboardContentType::Image)
            .count()
    }
}

/// Previews of a full history as the daemon sends them to the overlay.
pub fn history_previews(mix: HistoryMix) -> Vec<ClipboardItemPreview> {
    StateFixture::prefilled(StoreKind::Ephemeral, mix)
        .state
        .get_history()
}
