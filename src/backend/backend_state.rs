use super::selection::SelectionOwner;
use crate::backend::persistence::{open_persistent_store, read_db_password_from_keyring_once};
use crate::backend::store::{ClipboardStore, MAX_HISTORY_ITEMS, OpenBlob, next_item_id};
use crate::backend::virtual_keyboard::paste_via_virtual_keyboard;
use crate::backend::wayland_clipboard::is_internal_mime_type;
use crate::shared::config::{UserConfig, config_path, read_persistence_enabled};
use crate::shared::{
    ClipboardContentType, ClipboardItem, ClipboardItemPreview, PASSWORD_HINT_MIME,
};
use bytes::Bytes;
use fast_image_resize::{
    FilterType, IntoImageView, IntoImageViewMut, ResizeAlg, ResizeOptions, Resizer,
};
use image::{DynamicImage, ImageFormat, RgbImage, RgbaImage};
use indexmap::IndexMap;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use wayland_client::backend::ObjectId;

#[derive(Debug)]
pub struct BackendState {
    // Clipboard history and management
    pub history: Vec<ClipboardItem>,
    pub id_for_next_entry: u64,

    // Current clipboard data
    // Mapping of offer ObjectId -> list of MIME types provided by that offer
    pub mime_type_offers: HashMap<ObjectId, Vec<String>>,
    // Currently selected offer id (if any)
    pub current_data_offer: Option<ObjectId>,
    pub(super) selection: Option<SelectionOwner>,
    // If true, we only monitor external selections and DO NOT immediately
    // re-set (take ownership of) the newly received selection.
    // If false (default), after reading an external selection we immediately
    // set it ourselves so it persists even if the source app exits.
    pub monitor_only: bool,
    // Holds every payload on disk; persistent or session-only depending on the setting.
    store: ClipboardStore,
    db_password: Option<String>,
    pub expiry_notify: Arc<Notify>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self::new(false)
    }
}

impl BackendState {
    pub fn new(monitor_only: bool) -> Self {
        let db_password = match read_db_password_from_keyring_once() {
            Ok(password) => password,
            Err(e) => {
                warn!("Failed to read DB password from keyring at startup: {e}");
                None
            }
        };

        Self::with_password(monitor_only, db_password)
    }

    pub(super) fn with_password(monitor_only: bool, db_password: Option<String>) -> Self {
        let persistence_enabled = read_persistence_enabled(&config_path()).unwrap_or_else(|e| {
            eprintln!("cursor-clip: cannot load persistence setting. Starting with session-only history.\n{e}");
            false
        });
        let store = match ClipboardStore::open_ephemeral() {
            Ok(store) => store,
            Err(e) => panic!("Cannot create clipboard store: {e}"),
        };

        let mut state = Self {
            history: Vec::new(),
            mime_type_offers: HashMap::new(),
            id_for_next_entry: 1,
            current_data_offer: None,
            selection: None,
            monitor_only,
            store,
            db_password,
            expiry_notify: Arc::new(Notify::new()),
        };

        if let Err(e) = state.transition_persistence(persistence_enabled, || Ok(())) {
            warn!("Failed to initialize persistence from config: {e}");
        }

        state
    }

    /// Prepare and store a copy; see [`PreparedCopy::from_mime_map`] and
    /// [`Self::add_prepared_copy`].
    #[cfg(any(debug_assertions, test))]
    pub fn add_clipboard_item_from_mime_map(
        &mut self,
        mime_content: IndexMap<String, Bytes>,
    ) -> Option<u64> {
        let copy = PreparedCopy::from_mime_map(mime_content)?;
        self.add_prepared_copy(copy)
    }

    /// Store the payloads of `copy`, put it at the top of the unpinned
    /// entries (replacing older copies of the same content) and save the history.
    /// Returns the id of the new entry, or `None` if a payload cannot be stored.
    pub fn add_prepared_copy(&mut self, copy: PreparedCopy) -> Option<u64> {
        let PreparedCopy {
            mut mime_content,
            content_type,
            content_preview,
            thumbnail,
        } = copy;

        // The blobs only become durable together, when `history_changed` saves the index.
        let mut mime_blobs = IndexMap::with_capacity(mime_content.len());
        for (mime, data) in mime_content.drain(..) {
            match self.store.write_blob(&data) {
                Ok(id) => {
                    mime_blobs.insert(mime, id);
                }
                Err(e) => {
                    warn!("Failed to store clipboard payload ({mime}): {e}");
                    return None;
                }
            }
        }
        drop(mime_content);
        // The payloads are stored, so keep the copy; like an image that cannot
        // be thumbnailed, it is then shown by its text preview.
        let thumbnail = thumbnail.and_then(|jpeg| {
            self.store
                .write_thumbnail(jpeg)
                .inspect_err(|e| warn!("Failed to store clipboard thumbnail: {e}"))
                .ok()
        });

        let mut item = ClipboardItem {
            item_id: self.id_for_next_entry,
            content_type,
            content_preview,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            pinned: false,
            mime_blobs,
            thumbnail,
        };

        // Remove older copies of the same content; a re-copied pinned item stays pinned.
        let primary = item.primary_blob().map(str::to_owned);
        self.history.retain(|existing| {
            let duplicate = existing.primary_blob() == primary.as_deref();
            if duplicate {
                item.inherit_duplicate_metadata(existing);
            }
            !duplicate
        });
        let insert_index = if item.pinned {
            0
        } else {
            self.history
                .iter()
                .position(|existing| !existing.pinned)
                .unwrap_or(self.history.len())
        };
        self.history.insert(insert_index, item);
        if self.history.len() > MAX_HISTORY_ITEMS {
            self.history.truncate(MAX_HISTORY_ITEMS);
        }

        let new_id = self.id_for_next_entry;
        self.id_for_next_entry += 1;
        self.history_changed();
        release_freed_memory();
        Some(new_id)
    }

    #[cfg(any(debug_assertions, test))]
    pub fn add_clipboard_item_from_text(&mut self, text: &str) -> Option<u64> {
        let mut mime_content = IndexMap::new();
        mime_content.insert(
            "text/plain;charset=utf-8".to_string(),
            Bytes::copy_from_slice(text.as_bytes()),
        );
        self.add_clipboard_item_from_mime_map(mime_content)
    }

    pub fn get_history(&mut self) -> Vec<ClipboardItemPreview> {
        self.expire_password_items(unix_timestamp());
        self.history
            .iter()
            .map(ClipboardItemPreview::from)
            .collect()
    }

    pub fn get_item_by_id(&self, id: u64) -> Option<ClipboardItem> {
        let now = unix_timestamp();
        self.history
            .iter()
            .find(|i| i.item_id == id && !i.is_expired(now))
            .cloned()
    }

    pub fn next_password_expiry(&self) -> Option<u64> {
        self.history
            .iter()
            .filter_map(ClipboardItem::expires_at)
            .min()
    }

    /// Remove expired secrets, regardless of pin state, and release our selection.
    pub fn expire_password_items(&mut self, now: u64) {
        let expired_source = self.owned_entry_id().is_some_and(|id| {
            self.history
                .iter()
                .any(|item| item.item_id == id && item.is_expired(now))
        });
        let previous_len = self.history.len();
        self.history.retain(|item| !item.is_expired(now));
        if self.history.len() == previous_len {
            return;
        }
        if expired_source && let Some(owner) = &mut self.selection {
            owner.revoke();
        }
        self.history_changed();
    }

    /// Ignore selection offers while we own the clipboard to avoid reading our own source.
    pub(super) fn owned_entry_id(&self) -> Option<u64> {
        self.selection.as_ref()?.entry_id()
    }

    pub fn clear_history(&mut self) {
        self.history.clear();

        // If we clear history while owning a selection source, drop it and
        // re-enable selection reads so external copies keep being tracked.
        if let Some(owner) = &mut self.selection {
            owner.clear();
        }

        self.history_changed();
    }

    pub fn delete_item_by_id(&mut self, entry_id: u64) -> Result<(), String> {
        let index = self
            .history
            .iter()
            .position(|item| item.item_id == entry_id)
            .ok_or_else(|| format!("No clipboard item found with ID: {entry_id}"))?;

        self.history.remove(index);

        if let Some(owner) = &mut self.selection
            && owner.entry_id() == Some(entry_id)
        {
            owner.clear();
        }

        self.history_changed();

        Ok(())
    }

    pub fn set_clipboard_by_id(
        &mut self,
        entry_id: u64,
        instant_paste: bool,
    ) -> Result<(), String> {
        let item = self
            .get_item_by_id(entry_id)
            .ok_or_else(|| format!("No clipboard item found with ID: {entry_id}"))?;

        // History created before internal types were filtered may still contain them.
        let mut mimes = item
            .mime_blobs
            .keys()
            .filter(|mime| !is_internal_mime_type(mime))
            .peekable();
        if mimes.peek().is_none() {
            return Err(format!(
                "Clipboard item {entry_id} has no shareable MIME types"
            ));
        }

        info!("Setting clipboard content by ID {entry_id}");

        let typing_payload = if instant_paste
            && let Some((mime, charset)) = item.typing_format()
            && UserConfig::read(&config_path())
                .unwrap_or_default()
                .type_instead_of_paste
        {
            Some((self.open_item_payload(entry_id, mime)?, charset.to_owned()))
        } else {
            None
        };

        self.selection
            .as_mut()
            .ok_or("Wayland clipboard objects not available yet")?
            .publish(entry_id, mimes.cloned());
        debug!("Created clipboard source and set selection (id {entry_id})");

        if instant_paste {
            let expires_at = item.expires_at();
            std::thread::spawn(move || {
                // Wait for focus to return to the previous app before sending any keys.
                std::thread::sleep(std::time::Duration::from_millis(150));
                if expires_at.is_some_and(|expiry| expiry <= unix_timestamp()) {
                    return;
                }
                let result = match typing_payload {
                    Some((blob, charset)) => blob.read().and_then(|bytes| {
                        let text = decode_typing_text(bytes, &charset);
                        paste_via_virtual_keyboard(text.as_deref())
                    }),
                    None => paste_via_virtual_keyboard(None),
                };
                if let Err(e) = result {
                    warn!("Instant paste failed: {e}");
                }
            });
        }

        Ok(())
    }

    pub fn set_pinned(&mut self, entry_id: u64, pinned: bool) -> Result<(), String> {
        let index = self
            .history
            .iter()
            .position(|item| item.item_id == entry_id)
            .ok_or_else(|| format!("No clipboard item found with ID: {entry_id}"))?;

        let mut item = self.history.remove(index);
        item.pinned = pinned;

        let insert_index = if pinned {
            0
        } else {
            self.history
                .iter()
                .position(|existing| !existing.pinned)
                .unwrap_or(self.history.len())
        };

        self.history.insert(insert_index, item);
        self.history_changed();
        Ok(())
    }

    pub fn persistence_enabled(&self) -> bool {
        self.store.is_persistent()
    }

    pub fn set_persistence_enabled(&mut self, enabled: bool) -> Result<(), String> {
        self.transition_persistence(enabled, || {
            UserConfig::update(&config_path(), |config| {
                config.persistence_enabled = enabled
            })
        })
    }

    fn transition_persistence(
        &mut self,
        enabled: bool,
        commit_preference: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        if enabled == self.persistence_enabled() {
            return commit_preference();
        }

        let target = if enabled {
            open_persistent_store(&mut self.db_password)?
        } else {
            ClipboardStore::open_ephemeral()?
        };
        let now = unix_timestamp();
        if enabled {
            self.expire_password_items(now);
        }
        self.store
            .migrate_to(target, &mut self.history, now, commit_preference)?;
        self.id_for_next_entry = self.id_for_next_entry.max(next_item_id(&self.history));
        release_freed_memory();
        self.expiry_notify.notify_one();
        Ok(())
    }

    /// Open the payload of one MIME type of a history item. Reading and
    /// decrypting the opened blob can then happen without the backend lock.
    pub fn open_item_payload(&self, entry_id: u64, mime_type: &str) -> Result<OpenBlob, String> {
        if is_internal_mime_type(mime_type) {
            return Err(format!("Cannot serve internal MIME type {mime_type}"));
        }
        let item = self
            .history
            .iter()
            .find(|item| item.item_id == entry_id)
            .ok_or_else(|| format!("Clipboard item id {entry_id} no longer exists in history"))?;
        if item.is_expired(unix_timestamp()) {
            return Err(format!("Clipboard item id {entry_id} has expired"));
        }
        let blob = item
            .mime_blobs
            .get(mime_type)
            .ok_or_else(|| format!("No data stored for MIME {mime_type} (id {entry_id})"))?;
        self.store.open_blob(blob)
    }

    fn history_changed(&mut self) {
        self.expiry_notify.notify_one();
        // Blobs may only go away once an index without them is on disk;
        // otherwise a crash would leave the old index pointing at nothing.
        // Saving the index also makes blobs written since the last save durable.
        match self.store.save_index(&self.history) {
            Ok(()) => self.store.collect_garbage(&self.history),
            Err(e) => warn!("Persistence save failed: {e}"),
        }
    }
}

/// A clipboard copy that has been classified and thumbnailed but not stored yet.
///
/// Preparing needs no [`BackendState`], so the expensive part of ingesting a
/// copy (decoding and scaling an image) can run without holding the state
/// lock. It holds no store references either: a store switch between
/// preparing and [`BackendState::add_prepared_copy`] is harmless.
pub struct PreparedCopy {
    /// Offered payloads by MIME type; at least one is a non-empty payload
    /// other than the password hint.
    mime_content: IndexMap<String, Bytes>,
    content_type: ClipboardContentType,
    content_preview: String,
    /// JPEG thumbnail of an `image/png` payload.
    thumbnail: Option<Bytes>,
}

// Payloads may be secrets from a password manager; keep them out of logs.
impl std::fmt::Debug for PreparedCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCopy")
            .field("content_type", &self.content_type)
            .finish_non_exhaustive()
    }
}

impl PreparedCopy {
    /// Classify a copy and generate its preview text and thumbnail.
    ///
    /// Returns `None` for metadata-only offers (including password-manager
    /// clear updates), which do not become history entries.
    pub fn from_mime_map(mime_content: IndexMap<String, Bytes>) -> Option<Self> {
        if !mime_content
            .iter()
            .any(|(mime, data)| mime != PASSWORD_HINT_MIME && !data.is_empty())
        {
            return None;
        }
        let password_hint = mime_content.contains_key(PASSWORD_HINT_MIME);

        // If we have image/png, prefer showing mime_type + bytes and set type to Image
        let (content_preview, content_type, thumbnail) = if password_hint {
            let preview = [
                "text/plain;charset=utf-8",
                "text/plain",
                "UTF8_STRING",
                "TEXT",
                "STRING",
            ]
            .iter()
            .find_map(|mime| mime_content.get(*mime))
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(|text| text.chars().take(200).collect())
            .unwrap_or_else(|| "Password".to_string());
            (preview, ClipboardContentType::Password, None)
        } else if let Some(png_bytes) = mime_content.get("image/png") {
            (
                format!("<image/png {} bytes>", png_bytes.len()),
                ClipboardContentType::Image,
                scale_image(png_bytes),
            )
        } else {
            // Otherwise, if we have text/plain;charset=utf-8, show up to first 200 chars and infer type
            let preview: String =
                if let Some(txt_bytes) = mime_content.get("text/plain;charset=utf-8") {
                    match std::str::from_utf8(txt_bytes.as_ref()) {
                        Ok(s) => s.chars().take(200).collect(),
                        Err(_) => format!("<text/plain;charset=utf-8 {} bytes>", txt_bytes.len()),
                    }
                } else {
                    // Fallback: show placeholder using first mime entry
                    let (mime_name, len) = mime_content
                        .iter()
                        .next()
                        .map(|(k, v)| (k.clone(), v.len()))
                        .unwrap();
                    format!("<{mime_name} {len} bytes>")
                };
            let content_type = ClipboardContentType::type_from_preview(&preview);
            (preview, content_type, None)
        };

        Some(Self {
            mime_content,
            content_type,
            content_preview,
            thumbnail,
        })
    }
}

/// Decode a PNG and encode a JPEG thumbnail that fits into 300x180 pixels.
/// Returns `None` if the PNG cannot be decoded or the thumbnail cannot be encoded.
///
/// 8-bit RGB images are resized as they are. Every other layout is first
/// converted to 8-bit RGBA and resized with premultiplied alpha, unless every
/// pixel is opaque; the alpha channel is then dropped, so fully transparent
/// pixels become black. Resizing only these two layouts keeps the resize code
/// compiled into the binary small.
fn scale_image(png_bytes: &[u8]) -> Option<Bytes> {
    let source = image::load_from_memory_with_format(png_bytes, ImageFormat::Png).ok()?;
    let (width, height) = thumbnail_size(source.width(), source.height());
    let thumbnail = match source {
        DynamicImage::ImageRgb8(source) => {
            let mut thumbnail = RgbImage::new(width, height);
            resize(&source, &mut thumbnail, false)?;
            thumbnail
        }
        source => {
            let source = source.into_rgba8();
            let mut thumbnail = RgbaImage::new(width, height);
            resize(&source, &mut thumbnail, !is_opaque(&source))?;
            DynamicImage::ImageRgba8(thumbnail).into_rgb8()
        }
    };

    let mut buffer = Cursor::new(Vec::new());
    thumbnail.write_to(&mut buffer, ImageFormat::Jpeg).ok()?;
    Some(buffer.into_inner().into())
}

/// Bilinear resize of `source` to the size of `thumbnail`. `use_alpha`
/// premultiplies the colours by alpha first, which needs a full-size copy of
/// the image and changes nothing when every pixel is opaque.
fn resize(
    source: &impl IntoImageView,
    thumbnail: &mut impl IntoImageViewMut,
    use_alpha: bool,
) -> Option<()> {
    let options = ResizeOptions::new()
        .resize_alg(ResizeAlg::Convolution(FilterType::Bilinear))
        .use_alpha(use_alpha);
    Resizer::new().resize(source, thumbnail, &options).ok()
}

/// Whether every pixel of `image` is fully opaque.
fn is_opaque(image: &RgbaImage) -> bool {
    image.pixels().all(|pixel| pixel[3] == u8::MAX)
}

/// Largest size with the aspect ratio of `width`x`height` that fits into
/// 300x180 pixels, at least 1x1.
fn thumbnail_size(width: u32, height: u32) -> (u32, u32) {
    let scale = (300.0 / f64::from(width)).min(180.0 / f64::from(height));
    let scaled = |side: u32| ((f64::from(side) * scale).round() as u32).max(1);
    (scaled(width), scaled(height))
}

fn decode_typing_text(bytes: Vec<u8>, charset: &str) -> Option<String> {
    let utf8 = if charset.eq_ignore_ascii_case("UTF-8") {
        bytes
    } else {
        let (converted, consumed) = glib::convert(&bytes, "UTF-8", charset).ok()?;
        if consumed != bytes.len() {
            return None;
        }
        converted.into()
    };
    String::from_utf8(utf8).ok()
}

pub(super) fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Large clipboard payloads pass through the heap only briefly; hand the freed
/// pages back to the kernel so the daemon's RSS does not stay at its peak.
fn release_freed_memory() {
    // SAFETY: malloc_trim only releases free heap memory and has no preconditions.
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_previews_fit_the_bounds_and_remain_decodable_as_jpeg() {
        for (width, height, expected) in [(640, 320, (300, 150)), (1, 3, (60, 180))] {
            let mut png = Cursor::new(Vec::new());
            let transparent_red = RgbaImage::from_pixel(width, height, image::Rgba([255, 0, 0, 0]));
            image::DynamicImage::ImageRgba8(transparent_red)
                .write_to(&mut png, ImageFormat::Png)
                .unwrap();

            let preview = scale_image(png.get_ref()).unwrap();
            let decoded = image::load_from_memory_with_format(&preview, ImageFormat::Jpeg).unwrap();
            assert_eq!((decoded.width(), decoded.height()), expected);
            assert_eq!(decoded.to_rgb8().get_pixel(0, 0).0, [0, 0, 0]);
        }

        assert!(scale_image(b"invalid PNG").is_none());
    }

    /// Largest mean per-channel difference between thumbnails that were
    /// resized in different pixel layouts and are equal up to rounding. JPEG
    /// compression can turn a rounding difference into a larger one for single
    /// pixels in noisy blocks, so the mean is compared.
    const THUMBNAIL_TOLERANCE: f64 = 1.0;

    /// 16-bit RGBA test picture with gradients, fine detail and (if `alpha`)
    /// fully transparent, half transparent and opaque regions.
    fn test_picture(alpha: bool) -> DynamicImage {
        let (width, height) = (640, 360);
        let mut state = 0x2545_f491_u32;
        let picture = image::ImageBuffer::from_fn(width, height, |x, y| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let noise = (state >> 16) as u16;
            let detailed = (y / 30) % 3 == 0;
            let opacity = match (alpha, x * 3 / width) {
                (false, _) | (true, 2) => u16::MAX,
                (true, 1) => u16::MAX / 2,
                (true, _) => 0,
            };
            image::Rgba([
                if detailed { noise } else { (x * 100) as u16 },
                (y * 180) as u16,
                if detailed {
                    noise.rotate_left(7)
                } else {
                    40_000
                },
                opacity,
            ])
        });
        DynamicImage::ImageRgba16(picture)
    }

    fn encode_png(picture: &DynamicImage) -> Vec<u8> {
        let mut png = Cursor::new(Vec::new());
        picture.write_to(&mut png, ImageFormat::Png).unwrap();
        png.into_inner()
    }

    fn decode_jpeg(jpeg: &[u8]) -> image::RgbImage {
        image::load_from_memory_with_format(jpeg, ImageFormat::Jpeg)
            .unwrap()
            .into_rgb8()
    }

    /// The original thumbnail pipeline: every PNG was expanded to 8-bit RGBA
    /// and resized with premultiplied alpha, even when every pixel was opaque.
    fn rgba_pipeline_thumbnail(png: &[u8]) -> image::RgbImage {
        let source = image::load_from_memory_with_format(png, ImageFormat::Png)
            .unwrap()
            .into_rgba8();
        let (width, height) = thumbnail_size(source.width(), source.height());
        let mut thumbnail = image::RgbaImage::new(width, height);
        let options = ResizeOptions::new().resize_alg(ResizeAlg::Convolution(FilterType::Bilinear));
        Resizer::new()
            .resize(&source, &mut thumbnail, &options)
            .unwrap();
        let mut jpeg = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(thumbnail)
            .write_to(&mut jpeg, ImageFormat::Jpeg)
            .unwrap();
        decode_jpeg(jpeg.get_ref())
    }

    fn mean_channel_difference(a: &image::RgbImage, b: &image::RgbImage) -> f64 {
        assert_eq!(a.dimensions(), b.dimensions());
        let total: u64 = a
            .as_raw()
            .iter()
            .zip(b.as_raw())
            .map(|(a, b)| u64::from(a.abs_diff(*b)))
            .sum();
        total as f64 / a.as_raw().len() as f64
    }

    #[test]
    fn opaque_rgb_and_rgba_pngs_give_equivalent_thumbnails() {
        let picture = test_picture(false);
        let rgb = decode_jpeg(&scale_image(&encode_png(&picture.to_rgb8().into())).unwrap());
        let rgba = decode_jpeg(&scale_image(&encode_png(&picture.to_rgba8().into())).unwrap());

        assert!(mean_channel_difference(&rgb, &rgba) <= THUMBNAIL_TOLERANCE);
    }

    #[test]
    fn thumbnails_of_every_png_layout_match_the_rgba_pipeline() {
        let opaque = test_picture(false);
        let translucent = test_picture(true);
        let layouts: [(&str, DynamicImage); 9] = [
            ("L8", opaque.to_luma8().into()),
            ("La8", translucent.to_luma_alpha8().into()),
            ("Rgb8", opaque.to_rgb8().into()),
            ("Rgba8", translucent.to_rgba8().into()),
            ("opaque Rgba8", opaque.to_rgba8().into()),
            ("L16", opaque.to_luma16().into()),
            ("La16", translucent.to_luma_alpha16().into()),
            ("Rgb16", opaque.into_rgb16().into()),
            ("Rgba16", translucent),
        ];

        for (name, picture) in layouts {
            let png = encode_png(&picture);
            let decoded = image::load_from_memory_with_format(&png, ImageFormat::Png).unwrap();
            assert_eq!(decoded.color(), picture.color(), "{name}");

            // 8-bit RGB is resized with its own three-channel kernel; every other
            // layout goes through the RGBA pipeline and must match it exactly.
            let tolerance = if name == "Rgb8" {
                THUMBNAIL_TOLERANCE
            } else {
                0.0
            };
            let thumbnail = decode_jpeg(&scale_image(&png).unwrap());
            let difference = mean_channel_difference(&thumbnail, &rgba_pipeline_thumbnail(&png));
            assert!(difference <= tolerance, "{name}: {difference}");
        }
    }

    #[test]
    fn transparent_grey_and_16_bit_pixels_become_black() {
        let transparent = image::Rgba([u16::MAX, u16::MAX, u16::MAX, 0]);
        let picture =
            DynamicImage::ImageRgba16(image::ImageBuffer::from_pixel(40, 20, transparent));
        for layout in [
            DynamicImage::from(picture.to_luma_alpha8()),
            picture.to_luma_alpha16().into(),
            picture,
        ] {
            let thumbnail = decode_jpeg(&scale_image(&encode_png(&layout)).unwrap());
            assert_eq!(thumbnail.dimensions(), (300, 150));
            assert!(thumbnail.pixels().all(|pixel| pixel.0 == [0, 0, 0]));
        }
    }

    #[test]
    fn persistent_image_copy_keeps_thumbnail_blob_until_item_is_deleted() {
        let mut state = test_state(true);
        let mut png = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(RgbaImage::new(64, 32))
            .write_to(&mut png, ImageFormat::Png)
            .unwrap();
        let image_id = state
            .add_clipboard_item_from_mime_map(IndexMap::from([(
                "image/png".to_string(),
                Bytes::from(png.into_inner()),
            )]))
            .unwrap();
        state.add_clipboard_item_from_text("text entry").unwrap();
        let thumbnail = state.history[1].thumbnail.clone().unwrap();
        let thumbnail_blob = thumbnail.blob_id.unwrap();

        state.set_pinned(image_id, true).unwrap();
        let saved = state.store.load_index().unwrap();
        assert_eq!(saved[0].item_id, image_id);
        assert_eq!(saved[0].thumbnail.as_ref().unwrap().jpeg, thumbnail.jpeg);
        assert_eq!(
            state.store.get_blob(&thumbnail_blob).unwrap(),
            thumbnail.jpeg
        );

        state.delete_item_by_id(image_id).unwrap();
        assert!(state.store.get_blob(&thumbnail_blob).is_err());
        state.store.destroy().unwrap();
    }

    #[test]
    fn failed_preference_write_preserves_both_stores() {
        crate::test_support::isolated_test(|| {
            let mut old = BackendState::with_password(false, Some("test key".into()));
            old.add_clipboard_item_from_text("saved entry");
            old.set_persistence_enabled(true).unwrap();
            // Simulate an ephemeral session with a previous persistent index.
            UserConfig::update(&config_path(), |config| config.persistence_enabled = false)
                .unwrap();
            drop(old);
            let mut session = BackendState::with_password(false, Some("test key".into()));
            session.add_clipboard_item_from_text("session entry");
            std::fs::write(config_path(), "invalid TOML [").unwrap();
            assert!(session.set_persistence_enabled(true).is_err());
            assert!(!session.persistence_enabled());
            assert_eq!(session.get_history()[0].content_preview, "session entry");
            let disk = ClipboardStore::open_persistent("test key")
                .unwrap()
                .load_index()
                .unwrap();
            assert_eq!(disk.len(), 1);
            assert_eq!(disk[0].content_preview, "saved entry");
        });
    }

    #[tokio::test]
    async fn expiry_timer_wakes_for_new_earlier_deadline() {
        use std::sync::Mutex;
        use std::time::Duration;

        let state = Arc::new(Mutex::new(test_state(false)));
        state
            .lock()
            .unwrap()
            .add_clipboard_item_from_mime_map(password_mimes("later"))
            .unwrap();
        let task = tokio::spawn(crate::backend::ipc_server::expire_passwords(state.clone()));
        tokio::task::yield_now().await;
        let early_id = {
            let mut state = state.lock().unwrap();
            let id = state
                .add_clipboard_item_from_mime_map(password_mimes("earlier"))
                .unwrap();
            state
                .history
                .iter_mut()
                .find(|item| item.item_id == id)
                .unwrap()
                .timestamp = unix_timestamp() - 119;
            id
        };
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !state
                    .lock()
                    .unwrap()
                    .history
                    .iter()
                    .any(|item| item.item_id == early_id)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        task.abort();
        let _ = task.await;
        let state = Arc::try_unwrap(state).unwrap().into_inner().unwrap();
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.history[0].content_preview, "later");
        state.store.destroy().unwrap();
        result.unwrap();
    }

    fn test_state(persistent: bool) -> BackendState {
        BackendState {
            history: Vec::new(),
            id_for_next_entry: 1,
            mime_type_offers: HashMap::new(),
            current_data_offer: None,
            selection: None,
            monitor_only: false,
            store: ClipboardStore::isolated_test_store(persistent),
            db_password: None,
            expiry_notify: Arc::new(Notify::new()),
        }
    }

    fn password_mimes(text: &str) -> IndexMap<String, Bytes> {
        IndexMap::from([
            (
                "text/plain;charset=utf-8".to_string(),
                Bytes::copy_from_slice(text.as_bytes()),
            ),
            (PASSWORD_HINT_MIME.to_string(), Bytes::new()),
        ])
    }

    #[test]
    fn typing_uses_full_text_and_skips_image_and_file_offers() {
        let mut state = test_state(false);
        let text = "猫🙂".repeat(150);
        let mime = "text/plain; charset=UTF-8";
        let id = state
            .add_clipboard_item_from_mime_map(IndexMap::from([
                ("text/html".into(), Bytes::from_static(b"<b>preview</b>")),
                ("STRING".into(), Bytes::from_static(b"fallback")),
                (mime.into(), Bytes::copy_from_slice(text.as_bytes())),
            ]))
            .unwrap();
        let mut item = state.get_item_by_id(id).unwrap();
        let (format, charset) = item.typing_format().unwrap();
        assert_eq!(format, mime);
        let bytes = state.open_item_payload(id, format).unwrap().read().unwrap();
        assert_eq!(decode_typing_text(bytes, charset), Some(text));

        for non_text in [
            "image/png",
            "image/jpeg",
            "text/uri-list",
            "x-special/gnome-copied-files",
        ] {
            item.mime_blobs.insert(non_text.into(), String::new());
            assert_eq!(item.typing_format(), None);
            item.mime_blobs.shift_remove(non_text);
        }
        item.mime_blobs.shift_remove(mime);
        let (format, charset) = item.typing_format().unwrap();
        assert_eq!(format, "STRING");
        assert_eq!(
            decode_typing_text(vec![0xe9], charset).as_deref(),
            Some("é")
        );
        item.mime_blobs.shift_remove("STRING");
        assert_eq!(item.typing_format(), None);
        state.store.destroy().unwrap();
    }

    #[test]
    fn password_hint_overrides_text_url_code_file_and_image_classification() {
        let mut state = test_state(false);
        for text in [
            "plaintext",
            "https://example.com",
            "fn main() {}",
            "/home/file",
        ] {
            let mut mimes = password_mimes(text);
            mimes.insert("image/png".to_string(), Bytes::from_static(b"not an image"));
            let id = state.add_clipboard_item_from_mime_map(mimes).unwrap();
            let item = state.get_item_by_id(id).unwrap();
            assert_eq!(item.content_type, ClipboardContentType::Password);
            assert_eq!(item.content_preview, text);
            assert!(item.thumbnail.is_none());
            assert_eq!(item.expires_at(), Some(item.timestamp + 120));
        }
        state.store.destroy().unwrap();
    }

    #[test]
    fn hint_only_and_empty_password_updates_do_not_create_history_entries() {
        let mut state = test_state(false);
        let hint_only = IndexMap::from([(
            PASSWORD_HINT_MIME.to_string(),
            Bytes::from_static(b"secret"),
        )]);
        assert_eq!(state.add_clipboard_item_from_mime_map(hint_only), None);
        assert_eq!(
            state.add_clipboard_item_from_mime_map(password_mimes("")),
            None
        );
        assert!(state.history.is_empty());
        state.store.destroy().unwrap();
    }

    #[test]
    fn prepared_copies_are_classified_and_stored_as_history_entries() {
        let mut state = test_state(true);
        let png = Bytes::from(encode_png(&test_picture(false)));
        let image_preview = format!("<image/png {} bytes>", png.len());
        let cases = [
            (
                IndexMap::from([(
                    "text/plain;charset=utf-8".to_string(),
                    Bytes::from_static(b"https://example.com"),
                )]),
                ClipboardContentType::Url,
                "https://example.com",
            ),
            (
                password_mimes("hunter2"),
                ClipboardContentType::Password,
                "hunter2",
            ),
            (
                IndexMap::from([("image/png".to_string(), png.clone())]),
                ClipboardContentType::Image,
                image_preview.as_str(),
            ),
            (
                IndexMap::from([("text/html".to_string(), Bytes::from_static(b"<b>x</b>"))]),
                ClipboardContentType::Text,
                "<text/html 8 bytes>",
            ),
        ];

        for (mimes, content_type, preview) in cases {
            let copy = PreparedCopy::from_mime_map(mimes.clone()).unwrap();
            let id = state.add_prepared_copy(copy).unwrap();

            let item = &state.history[0];
            assert_eq!(item.item_id, id);
            assert_eq!(item.content_type, content_type);
            assert_eq!(item.content_preview, preview);
            assert!(item.mime_blobs.keys().eq(mimes.keys()));
            for (mime, data) in &mimes {
                assert_eq!(state.store.get_blob(&item.mime_blobs[mime]).unwrap(), *data);
            }
            let expected_thumbnail =
                (content_type == ClipboardContentType::Image).then(|| scale_image(&png).unwrap());
            let thumbnail = item.thumbnail.as_ref();
            assert_eq!(thumbnail.map(|t| &t.jpeg), expected_thumbnail.as_ref());
            if let Some(thumbnail) = thumbnail {
                let blob = thumbnail.blob_id.as_ref().unwrap();
                assert_eq!(state.store.get_blob(blob).unwrap(), thumbnail.jpeg);
            }
        }
        assert_eq!(state.history.len(), 4);
        state.store.destroy().unwrap();
    }

    #[test]
    fn copy_is_kept_without_thumbnail_when_thumbnail_cannot_be_stored() {
        use std::os::unix::fs::PermissionsExt;

        let mut state = test_state(true);
        let blob_dir = state.store.blob_dir();
        let png = Bytes::from(encode_png(&test_picture(false)));
        // The payload is already stored, so only writing the thumbnail needs
        // a new file in the read-only blob directory.
        state.store.put_blob(&png).unwrap();
        let set_mode = |mode| {
            std::fs::set_permissions(&blob_dir, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set_mode(0o500);
        if std::fs::File::create(blob_dir.join("probe")).is_ok() {
            // Permissions are not enforced (running as root): nothing can fail.
            set_mode(0o700);
            state.store.destroy().unwrap();
            return;
        }

        let id = state
            .add_clipboard_item_from_mime_map(IndexMap::from([("image/png".to_string(), png)]))
            .unwrap();
        set_mode(0o700);

        assert_eq!(state.history[0].item_id, id);
        assert_eq!(state.history[0].content_type, ClipboardContentType::Image);
        assert!(state.history[0].thumbnail.is_none());
        let saved = state.store.load_index().unwrap();
        assert_eq!(saved.len(), 1);
        assert!(saved[0].thumbnail.is_none());
        state.store.destroy().unwrap();
    }

    #[test]
    fn hint_only_and_empty_offers_are_not_prepared() {
        let hint_only = IndexMap::from([(
            PASSWORD_HINT_MIME.to_string(),
            Bytes::from_static(b"secret"),
        )]);
        for mimes in [hint_only, password_mimes(""), IndexMap::new()] {
            assert!(PreparedCopy::from_mime_map(mimes).is_none());
        }
    }

    #[test]
    fn pinned_password_expires_at_two_minutes_and_removes_persisted_payloads() {
        let mut state = test_state(true);
        let id = state
            .add_clipboard_item_from_mime_map(password_mimes("secret"))
            .unwrap();
        state.set_pinned(id, true).unwrap();
        let blob = state.history[0].mime_blobs["text/plain;charset=utf-8"].clone();
        let (owner, _peer) = crate::backend::selection::tests::test_owner(true);
        state.selection = Some(owner);
        state.set_clipboard_by_id(id, false).unwrap();
        state.history[0].timestamp = 100;
        state.expire_password_items(219);
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.store.get_blob(&blob).unwrap(), b"secret");
        state.expire_password_items(220);
        assert!(state.history.is_empty());
        assert!(state.store.load_index().unwrap().is_empty());
        assert!(state.store.get_blob(&blob).is_err());
        assert_eq!(state.owned_entry_id(), None);
        state.store.destroy().unwrap();
    }

    #[test]
    fn expiry_keeps_newer_selection_and_unmarked_passwords() {
        let mut state = test_state(false);
        state
            .add_clipboard_item_from_mime_map(password_mimes("secret"))
            .unwrap();
        state.history[0].timestamp = 100;
        let mut mimes = IndexMap::new();
        mimes.insert(
            "text/plain;charset=utf-8".to_string(),
            Bytes::from_static(b"NotSecret!"),
        );
        let newer_id = state.add_clipboard_item_from_mime_map(mimes).unwrap();
        let (owner, _peer) = crate::backend::selection::tests::test_owner(true);
        state.selection = Some(owner);
        state.set_clipboard_by_id(newer_id, false).unwrap();
        state.expire_password_items(220);
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.history[0].item_id, newer_id);
        assert_eq!(
            state.history[0].content_type,
            ClipboardContentType::Password
        );
        assert!(state.history[0].expires_at().is_none());
        assert_eq!(state.owned_entry_id(), Some(newer_id));
        state.store.destroy().unwrap();
    }

    #[test]
    fn copying_duplicate_without_hint_cannot_strip_password_expiry() {
        let mut state = test_state(false);
        let id = state
            .add_clipboard_item_from_mime_map(password_mimes("plaintext"))
            .unwrap();
        state.set_pinned(id, true).unwrap();
        state.history[0].timestamp = 100;
        let mimes = IndexMap::from([(
            "text/plain;charset=utf-8".to_string(),
            Bytes::from_static(b"plaintext"),
        )]);
        state.add_clipboard_item_from_mime_map(mimes).unwrap();
        assert_eq!(state.history.len(), 1);
        assert!(state.history[0].pinned);
        assert_eq!(
            state.history[0].content_type,
            ClipboardContentType::Password
        );
        assert_eq!(state.history[0].expires_at(), Some(220));
        state.expire_password_items(220);
        assert!(state.history.is_empty());
        state.store.destroy().unwrap();
    }

    #[test]
    fn expired_password_cannot_be_pasted_or_read_before_timer_runs() {
        let mut state = test_state(false);
        let id = state
            .add_clipboard_item_from_mime_map(password_mimes("secret"))
            .unwrap();
        state.history[0].timestamp = unix_timestamp().saturating_sub(120);
        assert!(state.get_item_by_id(id).is_none());
        assert!(
            state
                .open_item_payload(id, "text/plain;charset=utf-8")
                .is_err()
        );
        assert!(state.set_clipboard_by_id(id, false).is_err());
        assert!(state.get_history().is_empty());
        state.store.destroy().unwrap();
    }

    #[test]
    fn internal_mime_payloads_from_old_history_cannot_be_served() {
        let mut state = test_state(false);
        let internal_mime = "application/x-krita-node-internal-pointer";
        let id = state
            .add_clipboard_item_from_mime_map(IndexMap::from([(
                internal_mime.to_string(),
                Bytes::from_static(b"private data"),
            )]))
            .unwrap();

        assert_eq!(
            state.set_clipboard_by_id(id, false).unwrap_err(),
            format!("Clipboard item {id} has no shareable MIME types"),
        );
        assert!(state.open_item_payload(id, internal_mime).is_err());
        state.store.destroy().unwrap();
    }
}
