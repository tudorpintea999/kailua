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

//! Contains the accelerated version of the KZG point evaluation precompile.

use crate::precompiles::query_oracle;
use alloc::string::ToString;
use alloy_primitives::{Address, Bytes};
use revm::{
    precompile::{u64_to_address, Error as PrecompileError, PrecompileWithAddress},
    primitives::{Precompile, PrecompileOutput, PrecompileResult},
};

const POINT_EVAL_ADDRESS: Address = u64_to_address(0x0A);

pub(crate) const FPVM_KZG_POINT_EVAL: PrecompileWithAddress = PrecompileWithAddress(
    POINT_EVAL_ADDRESS,
    Precompile::Standard(fpvm_kzg_point_eval),
);

/// Performs an FPVM-accelerated KZG point evaluation precompile call.
fn fpvm_kzg_point_eval(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 50_000;

    if gas_limit < GAS_COST {
        return Err(PrecompileError::OutOfGas.into());
    }

    if input.len() != 192 {
        return Err(PrecompileError::BlobInvalidInputLength.into());
    }

    let result_data = kona_common::block_on(query_oracle(&POINT_EVAL_ADDRESS, input))
        .map_err(|e| PrecompileError::Other(e.to_string()))?;

    // todo: accelerated validation of point eval

    Ok(PrecompileOutput::new(GAS_COST, result_data.into()))
}
