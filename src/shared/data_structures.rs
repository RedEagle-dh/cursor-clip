use bytes::Bytes;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub const PASSWORD_HINT_MIME: &str = "x-kde-passwordManagerHint";
pub const PASSWORD_ENTRY_TTL_SECS: u64 = 120;

#[derive(Debug, Clone)]
pub struct ClipboardItem {
    pub item_id: u64,
    pub content_preview: String,
    pub content_type: ClipboardContentType,
    pub timestamp: u64, // Unix timestamp
    pub pinned: bool,
    // content type -> blob id; payloads live on disk in the clipboard store, not in memory
    pub mime_blobs: IndexMap<String, String>,
    pub thumbnail: Option<Thumbnail>,
}

/// JPEG preview of an image entry, kept in memory for the overlay.
#[derive(Debug, Clone)]
pub struct Thumbnail {
    pub jpeg: Bytes,
    /// Id of the blob holding `jpeg` in the store that holds the history.
    /// Only persistent stores keep thumbnails as blobs; for ephemeral stores
    /// this is `None`. Blob ids depend on the store, so the id is replaced
    /// whenever the history moves to another store.
    pub blob_id: Option<String>,
}

impl ClipboardItem {
    /// Preserve pins and carry forward password expiry when the newer copy lacks a hint.
    pub fn inherit_duplicate_metadata(&mut self, older: &Self) {
        self.pinned |= older.pinned;
        if !self.mime_blobs.contains_key(PASSWORD_HINT_MIME)
            && let Some(hint) = older.mime_blobs.get(PASSWORD_HINT_MIME)
        {
            self.mime_blobs
                .insert(PASSWORD_HINT_MIME.to_owned(), hint.clone());
            self.content_type = ClipboardContentType::Password;
            self.thumbnail = None;
            self.timestamp = older.timestamp;
        }
    }

    /// File managers and image applications may also offer a plain-text label.
    pub fn typing_format(&self) -> Option<(&str, &str)> {
        if self.content_type == ClipboardContentType::Image
            || self.mime_blobs.keys().any(|mime| {
                let media_type = mime.split(';').next().unwrap_or(mime).trim();
                media_type
                    .get(..6)
                    .is_some_and(|s| s.eq_ignore_ascii_case("image/"))
                    || media_type.eq_ignore_ascii_case("text/uri-list")
                    || media_type.eq_ignore_ascii_case("x-special/gnome-copied-files")
            })
        {
            return None;
        }

        self.mime_blobs
            .keys()
            .filter_map(|mime| {
                let mut parts = mime.split(';');
                let name = parts.next()?.trim();
                let (priority, charset) = if name.eq_ignore_ascii_case("text/plain") {
                    let charset = parts
                        .filter_map(|part| part.split_once('='))
                        .find(|(key, _)| key.trim().eq_ignore_ascii_case("charset"))
                        .map(|(_, value)| value.trim().trim_matches('"'));
                    match charset {
                        Some(value) if value.eq_ignore_ascii_case("utf-8") => (0, "UTF-8"),
                        None => (2, "UTF-8"),
                        Some(value) => (3, value),
                    }
                } else {
                    match name {
                        "UTF8_STRING" => (1, "UTF-8"),
                        "TEXT" => (4, "UTF-8"),
                        "STRING" => (5, "ISO-8859-1"),
                        _ => return None,
                    }
                };
                Some((priority, (mime.as_str(), charset)))
            })
            .min_by_key(|(priority, _)| *priority)
            .map(|(_, format)| format)
    }

    pub fn expires_at(&self) -> Option<u64> {
        self.mime_blobs
            .contains_key(PASSWORD_HINT_MIME)
            .then(|| self.timestamp.saturating_add(PASSWORD_ENTRY_TTL_SECS))
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at().is_some_and(|expires| expires <= now)
    }

    /// Blob holding the representation used to detect duplicate copies.
    pub fn primary_blob(&self) -> Option<&str> {
        const PRIMARY_MIMES: [&str; 4] = [
            "image/png",
            "text/plain;charset=utf-8",
            "text/plain",
            "UTF8_STRING",
        ];
        PRIMARY_MIMES
            .iter()
            .find_map(|mime| self.mime_blobs.get(*mime))
            .or_else(|| self.mime_blobs.values().next())
            .map(String::as_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardItemPreview {
    pub item_id: u64,
    pub content_preview: String,
    pub content_type: ClipboardContentType,
    pub timestamp: u64, // Unix timestamp
    #[serde(default)]
    pub pinned: bool,
    /// JPEG preview, sent as a base64 string (see `thumbnail_base64` below).
    #[serde(default, with = "thumbnail_base64")]
    pub thumbnail: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Wire format of [`ClipboardItemPreview::thumbnail`]: a standard base64
/// string with padding (RFC 4648), or `null`.
///
/// Up to version 1.1.0 the thumbnail was a JSON array with one number per
/// byte, which made the history reply several times larger and slow to
/// encode and decode. The daemon keeps running across package upgrades while
/// a new overlay starts on every open, so the reader also accepts that legacy
/// array. An overlay from 1.1.0 or earlier talking to a newer daemon reads the
/// base64 text as the raw image bytes; the image fails to decode and the row
/// shows its text preview instead of the picture.
mod thumbnail_base64 {
    use base64::Engine;
    use base64::display::Base64Display;
    use base64::engine::general_purpose::STANDARD;
    use bytes::Bytes;
    use serde::de::{self, Deserializer, SeqAccess, Visitor};
    use serde::ser::Serializer;
    use std::fmt;

    pub fn serialize<S: Serializer>(
        thumbnail: &Option<Bytes>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match thumbnail {
            // Streams the encoded text into the output without building a String.
            Some(jpeg) => serializer.collect_str(&Base64Display::new(jpeg, &STANDARD)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Bytes>, D::Error> {
        deserializer.deserialize_option(OptionVisitor)
    }

    struct OptionVisitor;

    impl<'de> Visitor<'de> for OptionVisitor {
        type Value = Option<Bytes>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a base64 string, an array of bytes or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(JpegVisitor).map(Some)
        }
    }

    struct JpegVisitor;

    impl<'de> Visitor<'de> for JpegVisitor {
        type Value = Bytes;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a base64 string or an array of bytes")
        }

        // serde_json lends strings without escapes straight from the input;
        // `visit_borrowed_str` forwards here, so no copy of the text is made.
        fn visit_str<E: de::Error>(self, encoded: &str) -> Result<Self::Value, E> {
            STANDARD
                .decode(encoded)
                .map(Bytes::from)
                .map_err(|e| E::custom(format_args!("invalid base64 thumbnail: {e}")))
        }

        // Legacy form written by daemons up to version 1.1.0.
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut jpeg = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64 * 1024));
            while let Some(byte) = seq.next_element::<u8>()? {
                jpeg.push(byte);
            }
            Ok(Bytes::from(jpeg))
        }
    }
}

impl From<&ClipboardItem> for ClipboardItemPreview {
    fn from(full: &ClipboardItem) -> Self {
        Self {
            item_id: full.item_id,
            content_preview: full.content_preview.clone(),
            content_type: full.content_type,
            timestamp: full.timestamp,
            pinned: full.pinned,
            thumbnail: full
                .thumbnail
                .as_ref()
                .map(|thumbnail| thumbnail.jpeg.clone()),
            expires_at: full.expires_at(),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClipboardContentType {
    Text,
    Url,
    Code,
    Password,
    File,
    Image,
    Other,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FrontendMessage {
    /// Request clipboard history
    GetHistory,
    /// Set clipboard content by ID
    SetClipboardById {
        id: u64,
        #[serde(default)]
        instant_paste: bool,
    },
    /// Set pinned state by ID
    SetPinned { id: u64, pinned: bool },
    /// Delete a single clipboard item by ID
    DeleteItemById { id: u64 },
    /// Clear all clipboard history
    ClearHistory,
    /// Read the current storage mode.
    GetHistoryPersistence,
    /// Enable or disable persistent history storage
    SetHistoryPersistence { enabled: bool },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BackendMessage {
    /// Response with clipboard history (previews only, no mime payloads)
    History { items: Vec<ClipboardItemPreview> },
    /// New clipboard item added (preview only)
    NewItem { item: ClipboardItemPreview },
    /// Clipboard content set successfully
    ClipboardSet,
    /// Clipboard item deleted
    ItemDeleted { id: u64 },
    /// Clipboard item pinned state updated
    ItemPinned { id: u64, pinned: bool },
    /// History cleared
    HistoryCleared,
    /// Persistence state was updated
    PersistenceState { enabled: bool },
    /// Error occurred
    Error { message: String },
}

impl ClipboardContentType {
    pub fn type_from_preview(content: &str) -> Self {
        const PASSWORD_SPECIALS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/\\|`~";
        if content.starts_with("http://") || content.starts_with("https://") {
            Self::Url
        } else if content.contains("fn ")
            || content.contains("impl ")
            || content.contains("struct ")
        {
            Self::Code
        } else if content.contains('/') && !content.contains(' ') && content.len() < 256 {
            Self::File
        } else if !content.is_empty()
            && content.len() < 50
            && !content.contains(' ')
            && content.chars().any(|c| PASSWORD_SPECIALS.contains(c))
        {
            Self::Password
        } else {
            Self::Text
        }
    }

    // Return a static string representation of the content type (future multi-language support)
    pub const fn as_str(self) -> &'static str {
        match self {
            // Return capitalized labels directly so callers don't need to post-process
            Self::Text => "Text",
            Self::Url => "Url",
            Self::Code => "Code",
            Self::Password => "Password",
            Self::File => "File",
            Self::Image => "Image",
            Self::Other => "Other",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Text => "📝",
            Self::Url => "🔗",
            Self::Code => "💻",
            Self::Password => "🔒",
            Self::File => "📁",
            Self::Image => "🖼️",
            Self::Other => "📄",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(thumbnail: Option<&'static [u8]>) -> ClipboardItemPreview {
        ClipboardItemPreview {
            item_id: 7,
            content_preview: "Image (2x2)".to_owned(),
            content_type: ClipboardContentType::Image,
            timestamp: 1_700_000_000,
            pinned: true,
            thumbnail: thumbnail.map(Bytes::from_static),
            expires_at: None,
        }
    }

    fn round_trip(item: &ClipboardItemPreview) -> ClipboardItemPreview {
        serde_json::from_str(&serde_json::to_string(item).unwrap()).unwrap()
    }

    #[test]
    fn preview_with_thumbnail_round_trips() {
        let item = preview(Some(b"\xff\xd8\xff\xe0 jpeg \x00\x01\xfe"));
        assert_eq!(round_trip(&item).thumbnail, item.thumbnail);
    }

    #[test]
    fn preview_without_thumbnail_round_trips() {
        assert_eq!(round_trip(&preview(None)).thumbnail, None);
    }

    #[test]
    fn thumbnail_is_sent_as_padded_standard_base64() {
        let json = serde_json::to_string(&preview(Some(b"\xfb\xff\xbf\x00\x01"))).unwrap();
        assert_eq!(
            json,
            r#"{"item_id":7,"content_preview":"Image (2x2)","content_type":"Image","timestamp":1700000000,"pinned":true,"thumbnail":"+/+/AAE="}"#
        );
    }

    #[test]
    fn missing_thumbnail_is_sent_as_null() {
        let json = serde_json::to_string(&preview(None)).unwrap();
        assert!(
            json.ends_with(r#","pinned":true,"thumbnail":null}"#),
            "{json}"
        );
    }

    #[test]
    fn legacy_byte_array_thumbnail_is_accepted() {
        let json = r#"{"item_id":7,"content_preview":"Image (2x2)","content_type":"Image","timestamp":1,"pinned":false,"thumbnail":[255,216,0,1]}"#;
        let item: ClipboardItemPreview = serde_json::from_str(json).unwrap();
        assert_eq!(item.thumbnail.as_deref(), Some(&[255, 216, 0, 1][..]));
    }

    #[test]
    fn invalid_base64_thumbnail_is_an_error() {
        let json = r#"{"item_id":7,"content_preview":"x","content_type":"Image","timestamp":1,"thumbnail":"not base64!"}"#;
        let error = serde_json::from_str::<ClipboardItemPreview>(json).unwrap_err();
        assert!(
            error.to_string().contains("invalid base64 thumbnail"),
            "{error}"
        );
    }

    #[test]
    fn out_of_range_legacy_byte_is_an_error() {
        let json = r#"{"item_id":7,"content_preview":"x","content_type":"Image","timestamp":1,"thumbnail":[256]}"#;
        assert!(serde_json::from_str::<ClipboardItemPreview>(json).is_err());
    }

    #[test]
    fn omitted_optional_fields_take_their_defaults() {
        let json = r#"{"item_id":7,"content_preview":"x","content_type":"Text","timestamp":1}"#;
        let item: ClipboardItemPreview = serde_json::from_str(json).unwrap();
        assert_eq!(
            (item.pinned, item.thumbnail, item.expires_at),
            (false, None, None)
        );
    }

    #[test]
    fn expires_at_is_sent_only_when_set() {
        let mut item = preview(None);
        item.expires_at = Some(1_700_000_120);
        let json = serde_json::to_string(&item).unwrap();
        assert!(
            json.ends_with(r#""thumbnail":null,"expires_at":1700000120}"#),
            "{json}"
        );
        assert_eq!(round_trip(&item).expires_at, Some(1_700_000_120));
    }

    #[test]
    fn history_reply_with_thumbnail_round_trips() {
        let message = BackendMessage::History {
            items: vec![preview(Some(b"jpeg")), preview(None)],
        };
        let json = serde_json::to_vec(&message).unwrap();
        let BackendMessage::History { items } = serde_json::from_slice(&json).unwrap() else {
            panic!("expected a history reply");
        };
        assert_eq!(items[0].thumbnail.as_deref(), Some(&b"jpeg"[..]));
        assert_eq!(items[1].thumbnail, None);
    }
}
