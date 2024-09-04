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

//! Contains the accelerated version of the `ecPairing` precompile.

use crate::precompiles::query_oracle;
use alloc::string::ToString;
use alloy_primitives::{Address, Bytes};
use revm::{
    precompile::{
        bn128::pair::{ISTANBUL_PAIR_BASE, ISTANBUL_PAIR_PER_POINT},
        u64_to_address, Error as PrecompileError, PrecompileWithAddress,
    },
    primitives::{Precompile, PrecompileOutput, PrecompileResult},
};

const ECPAIRING_ADDRESS: Address = u64_to_address(8);
const PAIR_ELEMENT_LEN: usize = 64 + 128;

pub(crate) const FPVM_ECPAIRING: PrecompileWithAddress =
    PrecompileWithAddress(ECPAIRING_ADDRESS, Precompile::Standard(fpvm_ecpairing));

/// Performs an FPVM-accelerated `ecpairing` precompile call.
fn fpvm_ecpairing(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let gas_used =
        (input.len() / PAIR_ELEMENT_LEN) as u64 * ISTANBUL_PAIR_PER_POINT + ISTANBUL_PAIR_BASE;

    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    if input.len() % PAIR_ELEMENT_LEN != 0 {
        return Err(PrecompileError::Bn128PairLength.into());
    }

    let result_data = kona_common::block_on(query_oracle(&ECPAIRING_ADDRESS, input))
        .map_err(|e| PrecompileError::Other(e.to_string()))?;

    // todo: accelerated validation of pairing

    Ok(PrecompileOutput::new(gas_used, result_data.into()))
}
