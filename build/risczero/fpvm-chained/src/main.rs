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

use kailua_common::BasicBootInfo;
use risc0_zkvm::guest::env;
use risc0_zkvm::serde::to_vec;

fn main() -> anyhow::Result<()> {
    let fpvm_image_id: [u32; 8] = env::read();
    let claim: BasicBootInfo = env::read();
    let chain: Vec<BasicBootInfo> = env::read();

    // We trust this value as it's set by the dispute game contract
    let mut last_confirmed_output = claim.l2_output_root;
    for block in chain {
        // Each block must have a valid receipt
        env::verify(fpvm_image_id, to_vec(&block)?.as_slice())?;
        // We must always refer to the same checkpointed L1 block hash in all proofs
        assert_eq!(block.l1_head, claim.l1_head);
        // The sequence of individual derivation blocks must be coherent
        assert_eq!(block.l2_output_root, last_confirmed_output);
        // All derivations must be under the same rollup config
        assert_eq!(block.config_hash, claim.config_hash);
        // The proof must end at the claim's height
        if block.l2_claim_block == claim.l2_claim_block {
            let is_fault_proof = block.l2_claim != claim.l2_claim;
            env::commit_slice(&claim.encode_packed(is_fault_proof, bytemuck::cast::<[u32; 8], [u8; 32]>(fpvm_image_id)));
            break;
        }
        // todo: handle case where block number is unreachable to enable fraud proofs
        // Update
        last_confirmed_output = block.l2_claim;
    }

    Ok(())
}
