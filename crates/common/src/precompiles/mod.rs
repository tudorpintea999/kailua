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

//! Contains the [PrecompileOverride] trait implementation for the FPVM-accelerated precompiles.

use crate::RISCZERO_ORACLE;
use alloc::sync::Arc;
use alloy_primitives::{keccak256, Address, Bytes};
use anyhow::ensure;
use kona_client::HintType;
use kona_executor::PrecompileOverride;
use kona_mpt::{TrieDB, TrieDBFetcher, TrieDBHinter};
use kona_preimage::{HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient};
use revm::{
    handler::register::EvmHandler, precompile::PrecompileSpecId, ContextPrecompiles, State,
};

mod bn128_pair;
mod ecrecover;
mod kzg_point_eval;

/// The [PrecompileOverride] implementation for the FPVM-accelerated precompiles.
#[derive(Debug)]
pub struct RISCZeroPrecompileOverride<F, H>
where
    F: TrieDBFetcher,
    H: TrieDBHinter,
{
    _phantom: core::marker::PhantomData<(F, H)>,
}

impl<F, H> Default for RISCZeroPrecompileOverride<F, H>
where
    F: TrieDBFetcher,
    H: TrieDBHinter,
{
    fn default() -> Self {
        Self {
            _phantom: core::marker::PhantomData::<(F, H)>,
        }
    }
}

impl<F, H> PrecompileOverride<F, H> for RISCZeroPrecompileOverride<F, H>
where
    F: TrieDBFetcher,
    H: TrieDBHinter,
{
    fn set_precompiles(handler: &mut EvmHandler<'_, (), &mut State<&mut TrieDB<F, H>>>) {
        let spec_id = handler.cfg.spec_id;

        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut ctx_precompiles =
                ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id)).clone();

            // Extend with FPVM-accelerated precompiles
            let override_precompiles = [
                ecrecover::FPVM_ECRECOVER,
                bn128_pair::FPVM_ECPAIRING,
                kzg_point_eval::FPVM_KZG_POINT_EVAL,
            ];
            ctx_precompiles.extend(override_precompiles);

            ctx_precompiles
        });
    }
}

pub async fn query_oracle(precompile_address: &Address, input: &Bytes) -> anyhow::Result<Vec<u8>> {
    // Write the hint for the ecrecover precompile run.
    let hint_data = &[precompile_address.as_ref(), input.as_ref()];
    RISCZERO_ORACLE
        .write(&HintType::L1Precompile.encode_with(hint_data))
        .await?;

    // Construct the key hash for the ecrecover precompile run.
    let raw_key_data = hint_data
        .iter()
        .copied()
        .flatten()
        .copied()
        .collect::<Vec<u8>>();
    let key_hash = keccak256(&raw_key_data);

    // Fetch the result of the ecrecover precompile run from the host.
    let result_data = RISCZERO_ORACLE
        .get(PreimageKey::new(*key_hash, PreimageKeyType::Precompile))
        .await?;

    // Ensure we've received valid result data.
    ensure!(!result_data.is_empty(), "Invalid result data");

    // Ensure we've not received an error from the host.
    ensure!(
        result_data[0] != 0,
        "Error executing ecrecover precompile in host"
    );

    // Return the result data.
    Ok(result_data[1..].to_vec())
}
