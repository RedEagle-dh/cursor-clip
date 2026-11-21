//! On-disk clipboard store.
//!
//! Clipboard payloads can be large (screenshots, rich text with embedded
//! images), so they are kept out of the daemon's memory. Every payload is
//! written once as an encrypted, content-addressed blob; history items only
//! keep blob ids plus a small preview and thumbnail.
//!
//! A persistent store lives in `$XDG_DATA_HOME/cursor-clip/store` and is keyed
//! by the password from the OS keyring. When persistent history is disabled an
//! ephemeral store with a random in-memory key is used instead, so payloads
//! are still never kept in RAM and become unreadable once the daemon exits.
//!
//! # Crash safety of persistent stores
//!
//! A history change writes its new blobs, then the index, then deletes the
//! blobs the new index no longer references:
//!
//! 1. Every new blob is written to a temporary file whose data is synced
//!    before it is renamed to its id, so a blob name never points at
//!    incomplete data ([`ClipboardStore::write_blob`]).
//! 2. The `blobs` directory is synced once for all blobs written since the
//!    last sync ([`ClipboardStore::save_index`] does this first).
//! 3. The index is replaced atomically and its directory is synced
//!    ([`write_atomic`]).
//! 4. Unreferenced blobs are deleted ([`ClipboardStore::collect_garbage`]).
//!
//! A crash before step 3 completes leaves the previous index, whose blobs are
//! all still present; new blobs that survive are complete and unreferenced
//! and are removed by the next garbage collection. A crash during step 3
//! leaves the old or the new index, and both only reference durable blobs:
//! the new one because of step 2, the old one because nothing was deleted
//! yet. Step 4 only starts once the new index is durable, so the old index
//! can no longer come back.
//!
//! Ephemeral stores skip every sync: their key only exists in memory and the
//! directory is wiped on the next start, so nothing in them can be read after
//! a crash anyway. They still write through a temporary file and a rename, so
//! a failed write never leaves a partial blob under its final name.

mod migration;
pub(super) use migration::{MAX_HISTORY_ITEMS, next_item_id};

use crate::shared::{ClipboardContentType, ClipboardItem, Thumbnail};
use crate::shared::{sync_dir, to_hex, write_atomic, write_renamed};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use bytes::Bytes;
use indexmap::IndexMap;
use log::{debug, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::collections::hash_map::{Entry, HashMap};
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Every sealed file starts with this magic followed by the nonce; the
/// ciphertext with its authentication tag appended follows the header.
const BLOB_MAGIC: &[u8; 4] = b"CCB1";
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = BLOB_MAGIC.len() + NONCE_LEN;
const TAG_LEN: usize = 16;
const INDEX_FILE: &str = "index.v1";
const BLOB_DIR: &str = "blobs";

/// Index entry as read from disk. Thumbnails are stored as blobs so the
/// index stays small enough to rewrite on every change.
#[derive(Deserialize)]
struct StoredItem {
    item_id: u64,
    content_preview: String,
    content_type: ClipboardContentType,
    timestamp: u64,
    pinned: bool,
    mime_blobs: IndexMap<String, String>,
    thumbnail_blob: Option<String>,
}

/// Index entry as written to disk, borrowed from the in-memory history.
/// Field names and order must match [`StoredItem`].
#[derive(Serialize)]
struct IndexEntry<'a> {
    item_id: u64,
    content_preview: &'a str,
    content_type: ClipboardContentType,
    timestamp: u64,
    pinned: bool,
    mime_blobs: &'a IndexMap<String, String>,
    thumbnail_blob: Option<&'a str>,
}

impl<'a> From<&'a ClipboardItem> for IndexEntry<'a> {
    fn from(item: &'a ClipboardItem) -> Self {
        Self {
            item_id: item.item_id,
            content_preview: &item.content_preview,
            content_type: item.content_type,
            timestamp: item.timestamp,
            pinned: item.pinned,
            mime_blobs: &item.mime_blobs,
            thumbnail_blob: thumbnail_blob_id(item),
        }
    }
}

pub struct ClipboardStore {
    dir: PathBuf,
    cipher: Aes256Gcm,
    id_key: [u8; 32],
    persistent: bool,
    /// Set while the `blobs` directory may hold entries that are not durable
    /// yet. Cleared only by a successful directory sync, so a blob that was
    /// deduplicated against such an entry is still synced before an index
    /// can reference it. Always false for ephemeral stores.
    unsynced_blobs: bool,
}

impl std::fmt::Debug for ClipboardStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardStore")
            .field("dir", &self.dir)
            .field("persistent", &self.persistent)
            .finish_non_exhaustive()
    }
}

impl ClipboardStore {
    #[cfg(test)]
    pub(super) fn isolated_test_store(persistent: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "cursor-clip-password-test-{}-{}",
            std::process::id(),
            rand::random::<u64>(),
        ));
        Self::open_at(dir, [7u8; 32], [9u8; 32], persistent).unwrap()
    }

    pub fn persistent_dir() -> PathBuf {
        xdg_dir("XDG_DATA_HOME", ".local/share")
            .join("cursor-clip")
            .join("store")
    }

    fn ephemeral_dir() -> PathBuf {
        xdg_dir("XDG_CACHE_HOME", ".cache")
            .join("cursor-clip")
            .join("session")
    }

    /// True if a persistent store with a history index exists on disk.
    pub(super) fn persistent_index_exists() -> Result<bool, String> {
        let path = Self::persistent_dir().join(INDEX_FILE);
        path.try_exists()
            .map_err(|e| format!("Cannot check {}: {e}", path.display()))
    }

    pub fn open_persistent(password: &str) -> Result<Self, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"cursor-clip store key v1");
        hasher.update(password.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"cursor-clip blob id v1");
        hasher.update(password.as_bytes());
        let id_key: [u8; 32] = hasher.finalize().into();

        Self::open_at(Self::persistent_dir(), key, id_key, true)
    }

    /// Open a fresh store whose key only exists in memory. Leftovers from a
    /// previous session are unreadable anyway, so they are removed first.
    pub fn open_ephemeral() -> Result<Self, String> {
        let dir = Self::ephemeral_dir();
        remove_dir_if_exists(&dir)?;

        let mut key = [0u8; 32];
        let mut id_key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut id_key);

        Self::open_at(dir, key, id_key, false)
    }

    fn open_at(
        dir: PathBuf,
        key: [u8; 32],
        id_key: [u8; 32],
        persistent: bool,
    ) -> Result<Self, String> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir.join(BLOB_DIR))
            .map_err(|e| format!("Failed to create store directory {}: {e}", dir.display()))?;

        let cipher = Aes256Gcm::new_from_slice(&key).expect("key must be 32 bytes");
        Ok(Self {
            dir,
            cipher,
            id_key,
            persistent,
            unsynced_blobs: false,
        })
    }

    pub const fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// Store a payload and return its id. Identical payloads share one blob.
    /// In a persistent store the blob is durable once this returns.
    #[cfg(test)]
    pub fn put_blob(&mut self, data: &[u8]) -> Result<String, String> {
        let id = self.write_blob(data)?;
        self.sync_blobs()?;
        Ok(id)
    }

    /// Store a payload like [`Self::put_blob`], but leave making its directory
    /// entry durable to the next [`Self::save_index`], so the blobs of one
    /// history change share a single directory sync.
    pub(in crate::backend) fn write_blob(&mut self, data: &[u8]) -> Result<String, String> {
        let id = self.blob_id(data);
        let path = self.blob_path(&id);
        if path.exists() {
            return Ok(id);
        }

        let sealed = self.seal(data)?;
        write_renamed(&path, &sealed, self.persistent)
            .map_err(|e| format!("Failed to write blob {id}: {e}"))?;
        if self.persistent {
            self.unsynced_blobs = true;
        }
        Ok(id)
    }

    /// Keep `jpeg` as the thumbnail of a history item. Persistent stores also
    /// write it as a blob (see [`Self::write_blob`]) so the index can refer to it.
    pub(in crate::backend) fn write_thumbnail(&mut self, jpeg: Bytes) -> Result<Thumbnail, String> {
        let blob_id = if self.persistent {
            Some(self.write_blob(&jpeg)?)
        } else {
            None
        };
        Ok(Thumbnail { jpeg, blob_id })
    }

    /// Make the directory entries of all blobs written so far durable.
    fn sync_blobs(&mut self) -> Result<(), String> {
        if !self.unsynced_blobs {
            return Ok(());
        }
        let blob_dir = self.dir.join(BLOB_DIR);
        sync_dir(&blob_dir).map_err(|e| format!("Failed to sync {}: {e}", blob_dir.display()))?;
        self.unsynced_blobs = false;
        Ok(())
    }

    pub fn get_blob(&self, id: &str) -> Result<Vec<u8>, String> {
        self.open_blob(id)?.read()
    }

    /// The open file stays readable after garbage collection or a store switch.
    pub fn open_blob(&self, id: &str) -> Result<OpenBlob, String> {
        if !is_blob_id(id) {
            return Err(format!("Invalid blob id: {id}"));
        }
        let file = fs::File::open(self.blob_path(id))
            .map_err(|e| format!("Failed to open blob {id}: {e}"))?;
        Ok(OpenBlob {
            file,
            cipher: self.cipher.clone(),
            id: id.to_owned(),
        })
    }

    /// Persist the history index. No-op for ephemeral stores.
    ///
    /// Every blob written before is made durable first, so the index never
    /// references a blob that could be lost in a crash.
    pub fn save_index(&mut self, history: &[ClipboardItem]) -> Result<(), String> {
        if !self.persistent {
            return Ok(());
        }
        debug_assert!(
            history
                .iter()
                .all(|item| item.thumbnail.as_ref().is_none_or(|t| t.blob_id.is_some())),
            "thumbnails of a persistent history are stored as blobs"
        );
        self.sync_blobs()?;

        let entries: Vec<IndexEntry<'_>> = history.iter().map(IndexEntry::from).collect();
        let mut buffer = sealed_buffer(0);
        serde_json::to_writer(&mut buffer, &entries)
            .map_err(|e| format!("Failed to serialize history index: {e}"))?;
        let sealed = self.seal_buffer(buffer)?;
        write_atomic(&self.dir.join(INDEX_FILE), &sealed)
    }

    fn read_index(&self) -> Result<Option<Vec<u8>>, String> {
        let path = self.dir.join(INDEX_FILE);
        match fs::read(&path) {
            Ok(sealed) => Ok(Some(sealed)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Failed to read history index: {e}")),
        }
    }

    #[cfg(test)]
    pub(super) fn blob_dir(&self) -> PathBuf {
        self.dir.join(BLOB_DIR)
    }

    #[cfg(test)]
    pub(super) fn load_index(&self) -> Result<Vec<ClipboardItem>, String> {
        match self.read_index()? {
            Some(sealed) => Ok(self.restore_items(self.decode_index(&sealed)?)),
            None => Ok(Vec::new()),
        }
    }

    fn decode_index(&self, sealed: &[u8]) -> Result<Vec<StoredItem>, String> {
        let (nonce, body) = split_header(sealed)?;
        let json = open_in_place(&self.cipher, &nonce, body.to_vec())?;
        serde_json::from_slice(&json).map_err(|e| format!("Failed to parse history index: {e}"))
    }

    fn restore_items(&self, stored: Vec<StoredItem>) -> Vec<ClipboardItem> {
        let mut items = Vec::with_capacity(stored.len());
        for entry in stored {
            let missing = entry
                .mime_blobs
                .values()
                .find(|id| !self.blob_path(id).exists());
            if let Some(id) = missing {
                warn!(
                    "Dropping history item {} with missing blob {id}",
                    entry.item_id
                );
                continue;
            }

            let thumbnail = entry
                .thumbnail_blob
                .and_then(|id| match self.get_blob(&id) {
                    Ok(jpeg) => Some(Thumbnail {
                        jpeg: jpeg.into(),
                        blob_id: Some(id),
                    }),
                    Err(e) => {
                        warn!("Failed to load thumbnail for item {}: {e}", entry.item_id);
                        None
                    }
                });

            items.push(ClipboardItem {
                item_id: entry.item_id,
                content_preview: entry.content_preview,
                content_type: entry.content_type,
                timestamp: entry.timestamp,
                pinned: entry.pinned,
                mime_blobs: entry.mime_blobs,
                thumbnail,
            });
        }

        items
    }

    /// Copy the blobs referenced by `history` into `target`, returning the
    /// history rewritten to the target's blob ids.
    ///
    /// The copies are not durable until `target` saves its index.
    fn transfer_to(
        &self,
        target: &mut Self,
        history: &[ClipboardItem],
    ) -> Result<Vec<ClipboardItem>, String> {
        // Items offer the same bytes under several MIME types: copy each blob once.
        let mut copied: HashMap<&str, String> = HashMap::new();
        let mut transferred = Vec::with_capacity(history.len());
        for item in history {
            let mut mime_blobs = IndexMap::with_capacity(item.mime_blobs.len());
            for (mime, id) in &item.mime_blobs {
                let target_id = match copied.entry(id) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        let target_id = target.write_blob(&self.get_blob(id)?)?;
                        entry.insert(target_id).clone()
                    }
                };
                mime_blobs.insert(mime.clone(), target_id);
            }
            let thumbnail = item
                .thumbnail
                .as_ref()
                .map(|thumbnail| target.write_thumbnail(thumbnail.jpeg.clone()))
                .transpose()?;
            transferred.push(ClipboardItem {
                item_id: item.item_id,
                content_preview: item.content_preview.clone(),
                content_type: item.content_type,
                timestamp: item.timestamp,
                pinned: item.pinned,
                mime_blobs,
                thumbnail,
            });
        }
        Ok(transferred)
    }

    /// Delete blobs that are no longer referenced by `history`.
    pub fn collect_garbage(&self, history: &[ClipboardItem]) {
        let referenced: HashSet<&str> = history
            .iter()
            .flat_map(|item| {
                item.mime_blobs
                    .values()
                    .map(String::as_str)
                    .chain(thumbnail_blob_id(item))
            })
            .collect();
        self.remove_unreferenced_blobs(|id| referenced.contains(id));
    }

    fn remove_unreferenced_blobs(&self, is_referenced: impl Fn(&str) -> bool) {
        let Ok(entries) = fs::read_dir(self.dir.join(BLOB_DIR)) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            // Unfinished atomic writes and unknown files are removed as well.
            if !is_referenced(name) {
                if let Err(e) = fs::remove_file(entry.path()) {
                    warn!("Failed to remove unreferenced blob {name}: {e}");
                } else {
                    debug!("Removed unreferenced blob {name}");
                }
            }
        }
    }

    /// Remove the store and everything in it.
    pub fn destroy(self) -> Result<(), String> {
        remove_dir_if_exists(&self.dir)
    }

    fn blob_id(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id_key);
        hasher.update(data);
        to_hex(&hasher.finalize())
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.dir.join(BLOB_DIR).join(id)
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut buffer = sealed_buffer(plaintext.len());
        buffer.extend_from_slice(plaintext);
        self.seal_buffer(buffer)
    }

    /// Encrypt the plaintext that follows the header of a [`sealed_buffer`]
    /// in place, fill in the header and append the authentication tag.
    fn seal_buffer(&self, mut buffer: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let (header, plaintext) = buffer.split_at_mut(HEADER_LEN);
        let (magic, header_nonce) = header.split_at_mut(BLOB_MAGIC.len());
        magic.copy_from_slice(BLOB_MAGIC);
        header_nonce.copy_from_slice(&nonce);

        let tag = self
            .cipher
            .encrypt_inout_detached(&Nonce::<Aes256Gcm>::from(nonce), &[], plaintext.into())
            .map_err(|e| format!("Encryption failed: {e}"))?;
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }
}

pub struct OpenBlob {
    file: fs::File,
    cipher: Aes256Gcm,
    id: String,
}

impl OpenBlob {
    /// Read and decrypt the blob. The header is read on its own so the
    /// ciphertext can be decrypted in the buffer it was read into.
    pub fn read(mut self) -> Result<Vec<u8>, String> {
        let mut header = [0u8; HEADER_LEN];
        self.file
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read blob {}: {e}", self.id))?;
        let (nonce, _) = split_header(&header)?;

        let mut body = Vec::new();
        self.file
            .read_to_end(&mut body)
            .map_err(|e| format!("Failed to read blob {}: {e}", self.id))?;
        open_in_place(&self.cipher, &nonce, body)
    }
}

/// Buffer for sealing a plaintext of `plaintext_len` bytes: a placeholder for
/// the header, with room for the plaintext and the tag that are appended.
fn sealed_buffer(plaintext_len: usize) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(HEADER_LEN + plaintext_len + TAG_LEN);
    buffer.resize(HEADER_LEN, 0);
    buffer
}

/// Split a sealed file into its nonce and the ciphertext with appended tag.
fn split_header(sealed: &[u8]) -> Result<(Nonce<Aes256Gcm>, &[u8]), String> {
    let rest = sealed
        .strip_prefix(BLOB_MAGIC.as_slice())
        .ok_or_else(|| "Unknown store file format".to_string())?;
    let (nonce, body) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or_else(|| "Truncated store file".to_string())?;
    Ok((Nonce::<Aes256Gcm>::from(*nonce), body))
}

/// Decrypt ciphertext with appended tag in place, returning the plaintext.
fn open_in_place(
    cipher: &Aes256Gcm,
    nonce: &Nonce<Aes256Gcm>,
    mut body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    cipher
        .decrypt_in_place(nonce, &[], &mut body)
        .map_err(|e| format!("Decryption failed: {e}"))?;
    Ok(body)
}

/// Blob id of the item's thumbnail in the store that holds the history.
fn thumbnail_blob_id(item: &ClipboardItem) -> Option<&str> {
    item.thumbnail.as_ref()?.blob_id.as_deref()
}

fn is_blob_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn xdg_dir(var: &str, home_fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(home_fallback)
        })
}

fn remove_dir_if_exists(dir: &Path) -> Result<(), String> {
    match fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed to remove {}: {e}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(persistent: bool) -> ClipboardStore {
        let mut suffix = [0u8; 8];
        rand::rng().fill_bytes(&mut suffix);
        let dir = std::env::temp_dir().join(format!(
            "cursor-clip-store-test-{}-{}",
            std::process::id(),
            to_hex(&suffix)
        ));
        ClipboardStore::open_at(dir, [7u8; 32], [9u8; 32], persistent).unwrap()
    }

    fn item(id: u64, blob: &str, thumbnail: Option<Thumbnail>) -> ClipboardItem {
        let mut mime_blobs = IndexMap::new();
        mime_blobs.insert("text/plain".to_string(), blob.to_string());
        ClipboardItem {
            item_id: id,
            content_preview: format!("item {id}"),
            content_type: ClipboardContentType::Text,
            timestamp: id,
            pinned: false,
            mime_blobs,
            thumbnail,
        }
    }

    fn blob_names(store: &ClipboardStore) -> HashSet<String> {
        fs::read_dir(store.dir.join(BLOB_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    }

    #[test]
    fn blobs_roundtrip_deduplicate_and_are_encrypted() {
        let mut store = test_store(false);
        let first = store.put_blob(b"secret clipboard text").unwrap();
        let second = store.put_blob(b"secret clipboard text").unwrap();
        assert_eq!(first, second);
        assert_eq!(store.get_blob(&first).unwrap(), b"secret clipboard text");

        let on_disk = fs::read(store.blob_path(&first)).unwrap();
        assert!(!on_disk.windows(6).any(|w| w == b"secret"));
        store.destroy().unwrap();
    }

    #[test]
    fn sealed_blob_keeps_file_format_and_rejects_tampering() {
        let mut store = test_store(false);
        let id = store.put_blob(b"payload").unwrap();
        let path = store.blob_path(&id);
        let mut on_disk = fs::read(&path).unwrap();
        assert_eq!(&on_disk[..4], BLOB_MAGIC);
        assert_eq!(on_disk.len(), HEADER_LEN + b"payload".len() + TAG_LEN);

        // Files written by the previous two-buffer implementation still open.
        let (nonce, body) = split_header(&on_disk).unwrap();
        let expected = aes_gcm::aead::Aead::encrypt(&store.cipher, &nonce, b"payload".as_slice());
        assert_eq!(body, expected.unwrap().as_slice());

        let last = on_disk.len() - 1;
        on_disk[last] ^= 1;
        fs::write(&path, &on_disk).unwrap();
        assert!(
            store
                .get_blob(&id)
                .unwrap_err()
                .starts_with("Decryption failed")
        );
        fs::write(&path, b"CCB1short").unwrap();
        assert!(store.get_blob(&id).is_err());
        store.destroy().unwrap();
    }

    #[test]
    fn ephemeral_blobs_never_wait_for_a_directory_sync() {
        let mut store = test_store(false);
        store.write_blob(b"session text").unwrap();
        store.write_thumbnail(Bytes::from_static(b"jpeg")).unwrap();
        assert!(!store.unsynced_blobs);
        store.destroy().unwrap();
    }

    #[test]
    fn persistent_index_save_syncs_pending_blobs_first() {
        let mut store = test_store(true);
        let id = store.write_blob(b"payload").unwrap();
        assert!(store.unsynced_blobs);
        // A duplicate keeps the directory marked until it has been synced.
        assert_eq!(store.write_blob(b"payload").unwrap(), id);
        assert!(store.unsynced_blobs);

        store.save_index(&[item(1, &id, None)]).unwrap();
        assert!(!store.unsynced_blobs);
        store.put_blob(b"other").unwrap();
        assert!(!store.unsynced_blobs);
        store.destroy().unwrap();
    }

    #[test]
    fn opened_blob_survives_garbage_collection() {
        let mut store = test_store(false);
        let id = store.put_blob(b"pasting this").unwrap();
        let opened = store.open_blob(&id).unwrap();

        store.collect_garbage(&[]);
        assert!(!store.blob_path(&id).exists());
        assert_eq!(opened.read().unwrap(), b"pasting this");
        store.destroy().unwrap();
    }

    #[test]
    fn index_roundtrip_and_garbage_collection() {
        let mut store = test_store(true);
        let kept = store.put_blob(b"kept").unwrap();
        let dropped = store.put_blob(b"dropped").unwrap();
        let thumbnail = store.write_thumbnail(Bytes::from_static(b"thumb")).unwrap();
        let thumbnail_id = thumbnail.blob_id.clone().unwrap();
        let history = vec![item(2, &kept, Some(thumbnail)), item(1, &kept, None)];

        store.save_index(&history).unwrap();
        store.collect_garbage(&history);
        assert_eq!(
            blob_names(&store),
            HashSet::from([kept.clone(), thumbnail_id.clone()])
        );
        assert!(!store.blob_path(&dropped).exists());

        let loaded = store.load_index().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].item_id, 2);
        let loaded_thumbnail = loaded[0].thumbnail.as_ref().unwrap();
        assert_eq!(loaded_thumbnail.jpeg.as_ref(), b"thumb");
        assert_eq!(
            loaded_thumbnail.blob_id.as_deref(),
            Some(thumbnail_id.as_str())
        );
        assert_eq!(loaded[1].mime_blobs["text/plain"], kept);

        // Dropping the item that owns the thumbnail frees its blob.
        store.collect_garbage(&loaded[1..]);
        assert_eq!(blob_names(&store), HashSet::from([kept]));
        store.destroy().unwrap();
    }

    #[test]
    fn index_json_matches_stored_item_layout() {
        let mut entry = item(3, "blob", None);
        entry.thumbnail = Some(Thumbnail {
            jpeg: Bytes::new(),
            blob_id: Some("thumb".into()),
        });
        let json = serde_json::to_string(&[IndexEntry::from(&entry)]).unwrap();
        assert_eq!(
            json,
            r#"[{"item_id":3,"content_preview":"item 3","content_type":"Text","timestamp":3,"pinned":false,"mime_blobs":{"text/plain":"blob"},"thumbnail_blob":"thumb"}]"#
        );
        let stored: Vec<StoredItem> = serde_json::from_str(&json).unwrap();
        assert_eq!(stored[0].thumbnail_blob.as_deref(), Some("thumb"));
    }

    #[test]
    fn transfer_rewrites_blob_ids_for_target_store() {
        let mut source = test_store(false);
        let mut target = ClipboardStore::open_at(
            source.dir.with_extension("target"),
            [1u8; 32],
            [2u8; 32],
            true,
        )
        .unwrap();
        let blob = source.put_blob(b"payload").unwrap();

        let moved = source
            .transfer_to(&mut target, &[item(1, &blob, None)])
            .unwrap();
        let new_id = &moved[0].mime_blobs["text/plain"];
        assert_ne!(new_id, &blob);
        assert_eq!(target.get_blob(new_id).unwrap(), b"payload");

        source.destroy().unwrap();
        target.destroy().unwrap();
    }

    #[test]
    fn transfer_copies_shared_blobs_once_and_moves_thumbnail_ids() {
        let mut session = test_store(false);
        let mut persistent = ClipboardStore::open_at(
            session.dir.with_extension("target"),
            [1u8; 32],
            [2u8; 32],
            true,
        )
        .unwrap();
        let text = session.put_blob(b"same text").unwrap();
        let mut entry = item(1, &text, None);
        entry.mime_blobs.insert("UTF8_STRING".into(), text.clone());
        entry.thumbnail = Some(
            session
                .write_thumbnail(Bytes::from_static(b"jpeg"))
                .unwrap(),
        );
        assert_eq!(entry.thumbnail.as_ref().unwrap().blob_id, None);

        let saved = session.transfer_to(&mut persistent, &[entry]).unwrap();
        let target_text = persistent.blob_id(b"same text");
        let target_thumbnail = persistent.blob_id(b"jpeg");
        assert_eq!(saved[0].mime_blobs["text/plain"], target_text);
        assert_eq!(saved[0].mime_blobs["UTF8_STRING"], target_text);
        assert_eq!(
            thumbnail_blob_id(&saved[0]),
            Some(target_thumbnail.as_str())
        );
        assert_eq!(
            blob_names(&persistent),
            HashSet::from([target_text, target_thumbnail])
        );
        assert!(persistent.unsynced_blobs);
        persistent.save_index(&saved).unwrap();
        assert!(!persistent.unsynced_blobs);

        // Back to a session store: payloads move, thumbnails stay in memory only.
        let back = persistent.transfer_to(&mut session, &saved).unwrap();
        assert_eq!(back[0].mime_blobs["text/plain"], text);
        let thumbnail = back[0].thumbnail.as_ref().unwrap();
        assert_eq!(thumbnail.jpeg.as_ref(), b"jpeg");
        assert_eq!(thumbnail.blob_id, None);

        session.destroy().unwrap();
        persistent.destroy().unwrap();
    }
}
