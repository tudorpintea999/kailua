// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate alloc;

// use anyhow::anyhow;
use async_trait::async_trait;
use c_kzg::KzgSettings;
use kona_derive::errors::BlobProviderError;
use kona_derive::traits::BlobProvider;
use kona_primitives::{Blob, BlockInfo, IndexedBlobHash};
use lazy_static::lazy_static;
// use risc0_zkvm::sha::{Impl as SHA2, Sha256};

#[cfg_attr(target_os = "zkvm", c_kzg::risc0_c_kzg_alloc_mod)]
pub mod c_kzg_alloc {
    // proc macro inserts calloc/malloc/free definitions here
}

lazy_static! {
    /// KZG Ceremony data
    pub static ref KZG: (Vec<u8>, KzgSettings) = {
        let mut data = Vec::from(include_bytes!("../kzg_settings_raw.bin"));
        let settings = KzgSettings::from_u8_slice(&mut data);
        (data, settings)
    };
}

/// An untrusted-oracle-backed blob provider.
#[derive(Debug, Clone)]
pub struct RISCZeroBlobProvider<P: BlobProvider> {
    blob_provider: P,
}

impl<P: BlobProvider> RISCZeroBlobProvider<P> {
    /// Constructs a new `RISCZeroBlobProvider`.
    pub fn new(blob_provider: P) -> Self {
        Self { blob_provider }
    }
}

#[async_trait]
impl<P: BlobProvider + Sync + Send> BlobProvider for RISCZeroBlobProvider<P> {
    async fn get_blobs(
        &mut self,
        block_ref: &BlockInfo,
        blob_hashes: &[IndexedBlobHash],
    ) -> Result<Vec<Blob>, BlobProviderError> {
        risc0_zkvm::guest::env::log(&format!(
            "Validating {} blob hashes for L1 block {} ({}).",
            blob_hashes.len(),
            block_ref.number,
            block_ref.hash
        ));
        let blobs = self.blob_provider.get_blobs(block_ref, blob_hashes).await?;
        risc0_zkvm::guest::env::log(&format!("Loaded {} blobs from oracle.", blobs.len()));
        assert_eq!(blob_hashes.len(), blobs.len());
        risc0_zkvm::guest::env::log("(INSECURE) Validation skipped.");
        // for (blob, indexed_blob_hash) in core::iter::zip(&blobs, blob_hashes) {
        //     let blob = c_kzg::Blob::from_bytes(blob.as_slice())
        //         .expect("Failed to construct c_kzg blob from bytes");
        //     let kzg_commitment = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, &KZG.1)
        //         .expect("Failed to convert blob to commitment");
        //     let versioned_hash_bytes: versioned_commitment(kzg_commitment.as_slice());
        //     if indexed_blob_hash.hash.0 != versioned_hash_bytes {
        //         risc0_zkvm::guest::env::log("blobs are bad..");
        //         return Err(BlobProviderError::Custom(anyhow!("Blob hash mismatch")));
        //     }
        //     risc0_zkvm::guest::env::log("Blob validated");
        // }
        Ok(blobs)
    }
}
