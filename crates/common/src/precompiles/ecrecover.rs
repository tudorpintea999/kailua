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

//! Contains the accelerated version of the `ecrecover` precompile.

use crate::precompiles::query_oracle;
use alloc::string::ToString;
use alloy_primitives::{Address, Bytes};
use revm::{
    precompile::{u64_to_address, Error as PrecompileError, PrecompileWithAddress},
    primitives::{Precompile, PrecompileOutput, PrecompileResult},
};

const ECRECOVER_ADDRESS: Address = u64_to_address(1);

pub(crate) const FPVM_ECRECOVER: PrecompileWithAddress =
    PrecompileWithAddress(ECRECOVER_ADDRESS, Precompile::Standard(fpvm_ecrecover));

/// Performs an FPVM-accelerated `ecrecover` precompile call.
fn fpvm_ecrecover(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const ECRECOVER_BASE: u64 = 3_000;

    if ECRECOVER_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    let result_data = kona_common::block_on(query_oracle(&ECRECOVER_ADDRESS, input))
        .map_err(|e| PrecompileError::Other(e.to_string()))?;

    // todo: accelerated validation of signer address

    Ok(PrecompileOutput::new(ECRECOVER_BASE, result_data.into()))
}
