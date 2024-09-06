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

use alloy_primitives::B256;
use kona_client::BootInfo;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "zkvm")]
pub mod blobs;
pub mod oracle;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct BasicBootInfo {
    /// The L1 head hash containing the safe L2 chain data that may reproduce the L2 head hash.
    pub l1_head: B256,
    /// The latest finalized L2 output root.
    pub l2_output_root: B256,
    /// The L2 output root claim.
    pub l2_claim: B256,
    /// The L2 claim block number.
    pub l2_claim_block: u64,
    /// The L2 chain ID.
    pub chain_id: u64,
}

impl From<BootInfo> for BasicBootInfo {
    fn from(value: BootInfo) -> Self {
        Self {
            l1_head: value.l1_head,
            l2_output_root: value.l2_output_root,
            l2_claim: value.l2_claim,
            l2_claim_block: value.l2_claim_block,
            chain_id: value.chain_id,
        }
    }
}

impl BasicBootInfo {
    pub fn encode_packed(&self, validity: bool) -> Vec<u8> {
        [
            self.l1_head.as_slice(),
            self.l2_output_root.as_slice(),
            self.l2_claim.as_slice(),
            self.l2_claim_block.to_be_bytes().as_slice(),
            self.chain_id.to_be_bytes().as_slice(),
            &[validity as u8],
        ]
        .concat()
    }
}
