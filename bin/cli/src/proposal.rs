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

use alloy::primitives::{Address, FixedBytes};
use alloy_rpc_types_beacon::sidecar::BlobData;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct Proposal {
    pub factory_index: u64,
    pub game_address: Address,
    pub parent_local_index: usize,
    pub intermediate_output_blob: Option<BlobData>,
    pub output_root: FixedBytes<32>,
    pub output_block_number: u64,
    pub challenged: HashSet<u32>,
    pub proven: HashMap<u32, bool>,
    pub resolved: HashSet<u32>,
    pub correct: Vec<bool>,
    pub is_correct_parent: bool,
}

impl Proposal {
    pub fn is_correct(&self) -> bool {
        self.is_correct_parent && self.correct.iter().all(|&x| x)
    }

    pub fn is_challenged(&self) -> bool {
        !self.challenged.is_empty()
    }

    pub fn is_game_resolved(&self) -> bool {
        self.resolved.contains(&0)
    }

    pub fn is_game_challenged(&self) -> bool {
        self.challenged.contains(&0)
    }

    pub fn is_game_proven(&self) -> Option<bool> {
        self.proven.get(&0).copied()
    }

    pub fn is_output_resolved(&self, output_number: u32) -> bool {
        self.resolved.contains(&output_number)
    }

    pub fn is_output_challenged(&self, output_number: u32) -> bool {
        self.challenged.contains(&output_number)
    }

    pub fn is_output_proven(&self, output_number: u32) -> Option<bool> {
        self.proven.get(&output_number).copied()
    }
}
