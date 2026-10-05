//! A lean browser projection of the existing bounded immutable sync stream.

use anyhow::Result;
use serde::Serialize;

use super::BlobRepo;

#[derive(Serialize)]
pub(crate) struct BrowserBlob {
    id: String,
    ciphertext: String,
    nonce: String,
    updated_at: String,
    deleted: bool,
}

#[derive(Serialize)]
pub(crate) struct BrowserPage {
    epoch: String,
    until: i64,
    cursor: i64,
    has_more: bool,
    blobs: Vec<BrowserBlob>,
}

impl BlobRepo {
    /// Browser pages omit vectors and rejected operations without changing client payloads.
    pub(crate) fn browser_page(
        &self,
        user: &str,
        epoch: &str,
        after: i64,
        until: Option<i64>,
        snapshot: bool,
    ) -> Result<BrowserPage> {
        let page = self.sync_page_with_view(user, epoch, after, until, snapshot, true)?;
        let blobs = page.changes.into_iter().map(|change| BrowserBlob {
            id: change.blob.id,
            ciphertext: change.blob.ciphertext,
            nonce: change.blob.nonce,
            updated_at: change.blob.updated_at,
            deleted: change.blob.deleted,
        }).collect();
        Ok(BrowserPage { epoch: page.epoch, until: page.until, cursor: page.cursor,
            has_more: page.has_more, blobs })
    }
}
