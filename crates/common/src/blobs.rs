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

use alloy_eips::eip4844::{kzg_to_versioned_hash, BYTES_PER_BLOB, BYTES_PER_COMMITMENT};
use anyhow::anyhow;
// use anyhow::anyhow;
use crate::oracle::{send_slice_recv_vec, BlobFetchRequest, FPVM_GET_BLOB};
use async_trait::async_trait;
use c_kzg::{Bytes48, KzgSettings};
use kona_derive::errors::BlobProviderError;
use kona_derive::traits::BlobProvider;
use kona_primitives::{Blob, BlockInfo, IndexedBlobHash};
use lazy_static::lazy_static;
use risc0_zkvm::serde::to_vec;

// use risc0_zkvm::sha::{Impl as SHA2, Sha256};

#[cfg_attr(target_os = "zkvm", c_kzg::risc0_c_kzg_alloc_mod)]
pub mod c_kzg_alloc {
    // proc macro inserts calloc/malloc/free definitions here
}

#[no_mangle]
pub extern "C" fn __assert_func(_file: *const i8, _line: i32, _func: *const i8, _expr: *const i8) {
    panic!("c_kzg assertion failure.");
}

// todo: use settings from alloy eips
lazy_static! {
    /// KZG Ceremony data
    pub static ref KZG: (Vec<u8>, KzgSettings) = {
        let mut data = Vec::from(include_bytes!("../kzg_settings_raw.bin"));
        let settings = KzgSettings::from_u8_slice(&mut data);
        (data, settings)
    };
}

/// An untrusted-oracle-backed blob provider.
#[derive(Debug, Clone, Default)]
pub struct RISCZeroBlobProvider;

#[async_trait]
impl BlobProvider for RISCZeroBlobProvider {
    async fn get_blobs(
        &mut self,
        block_ref: &BlockInfo,
        blob_hashes: &[IndexedBlobHash],
    ) -> Result<Vec<Blob>, BlobProviderError> {
        risc0_zkvm::guest::env::log(&format!(
            "Fetching {} blob hashes for L1 block {} ({}).",
            blob_hashes.len(),
            block_ref.number,
            block_ref.hash
        ));
        let mut blobs = Vec::with_capacity(blob_hashes.len());
        let mut commitments = Vec::with_capacity(blob_hashes.len());
        let mut proofs = Vec::with_capacity(blob_hashes.len());
        for blob_hash in blob_hashes {
            let request = to_vec(&BlobFetchRequest {
                block_ref: block_ref.clone(),
                blob_hash: blob_hash.clone(),
            })
            .expect("Failed to serialize blob request");
            let blob_vec: Vec<u8> = send_slice_recv_vec(FPVM_GET_BLOB, request.as_slice());
            blobs.push(
                c_kzg::Blob::from_bytes(&blob_vec[..BYTES_PER_BLOB])
                    .expect("Failed to deserialize blob"),
            );

            commitments.push(
                Bytes48::from_bytes(
                    &blob_vec[BYTES_PER_BLOB..BYTES_PER_BLOB + BYTES_PER_COMMITMENT],
                )
                .expect("Failed to deserialize kzg commitment"),
            );

            proofs.push(
                Bytes48::from_bytes(&blob_vec[BYTES_PER_BLOB + BYTES_PER_COMMITMENT..])
                    .expect("Failed to deserialize kzg proof"),
            );
        }
        // let blobs = self.blob_provider.get_blobs(block_ref, blob_hashes).await?;
        risc0_zkvm::guest::env::log(&format!("Loaded {} blobs from oracle.", blobs.len()));
        if blob_hashes.len() != blobs.len() {
            return Err(BlobProviderError::Custom(anyhow!("Missing blobs.")));
        }
        // verify commitments
        // todo: amortize over entire session
        c_kzg::KzgProof::verify_blob_kzg_proof_batch(
            blobs.as_slice(),
            commitments.as_slice(),
            proofs.as_slice(),
            &KZG.1,
        )
        .expect("Failed to batch validate kzg proofs");
        risc0_zkvm::guest::env::log("Blob commitments validated.");
        // Validate commitment hashes
        for (commitment, blob_hash) in core::iter::zip(&commitments, blob_hashes) {
            let versioned_hash = kzg_to_versioned_hash(commitment.as_slice());
            if versioned_hash != blob_hash.hash {
                return Err(BlobProviderError::Custom(anyhow!("Invalid blob hash.")));
            }
        }
        risc0_zkvm::guest::env::log("Blob hashes validated.");
        Ok(blobs.into_iter().map(|b| Blob::from(*b)).collect())
    }
}
