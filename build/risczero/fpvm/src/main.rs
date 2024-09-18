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

use kailua_common::blobs::RISCZeroBlobProvider;
use kailua_common::client::run_client;
use kailua_common::oracle::{CachingRISCZeroOracle, ORACLE_LRU_SIZE};
use kailua_common::ProofJournal;
use kona_client::l1::OracleBlobProvider;
use kona_client::BootInfo;
use risc0_zkvm::guest::env;
use std::sync::Arc;

fn main() {
    let oracle = Arc::new(CachingRISCZeroOracle::new(ORACLE_LRU_SIZE));
    let boot = kona_common::block_on(async {
        BootInfo::load(oracle.as_ref())
            .await
            .expect("Failed to load BootInfo")
    });
    let beacon = RISCZeroBlobProvider::new(OracleBlobProvider::new(oracle.clone()));
    // Attempt to recompute the output hash at the target block number using the kona client
    let real_output_hash =
        run_client(oracle, Arc::new(boot.clone()), beacon).expect("Failed to compute output hash.");
    // True iff l1 data is sufficient to recompute the same output hash
    let is_valid = real_output_hash
        .map(|computed_output| computed_output == boot.l2_claim)
        .unwrap_or_default();
    // Write the proof journal
    let proof_journal = ProofJournal::from(boot);
    env::commit_slice(&proof_journal.encode_packed(!is_valid));
}
