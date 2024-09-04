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

pub mod native;
pub mod oracle;

use alloy_primitives::B256;
use kailua_build::{KAILUA_FPVM_ELF, KAILUA_FPVM_ID};
use kailua_common::oracle::{FPVM_GET_PREIMAGE, FPVM_WRITE_HINT, ORACLE_LRU_SIZE};
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use oracle::CachingOracle;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::sync::Arc;
use tokio::join;
use tokio::runtime::Handle;
use tokio::task::spawn_blocking;

pub async fn run_zkvm_client() -> anyhow::Result<Receipt> {
    let client_task = spawn_blocking(|| {
        let oracle = Arc::new(CachingOracle::new(ORACLE_LRU_SIZE));
        let env = ExecutorEnv::builder()
            .io_callback(FPVM_GET_PREIMAGE, |key| {
                let byte_vec = key.to_vec();
                let byte_arr: [u8; 32] = byte_vec.as_slice().try_into()?;
                let res =
                    Handle::current().block_on(async { oracle.get(byte_arr.try_into()?).await })?;
                Ok(res.into())
            })
            .io_callback(FPVM_WRITE_HINT, |hint| {
                let byte_vec = Vec::<u8>::from(&hint.to_vec()[4..]);
                let string = String::from_utf8(byte_vec)?;
                Handle::current().block_on(async { oracle.write(&string).await })?;
                Ok(vec![1u8].into())
            })
            .build()?;
        let prover = default_prover();
        let prove_info = prover.prove(env, KAILUA_FPVM_ELF)?;
        println!(
            "STARK proof of {} total cycles ({} user cycles) computed.",
            prove_info.stats.total_cycles, prove_info.stats.user_cycles
        );
        prove_info.receipt.verify(KAILUA_FPVM_ID)?;
        Ok::<_, anyhow::Error>(prove_info.receipt)
    });
    join!(client_task).0?
}

pub fn fpvm_proof_file_name(l1_head: B256, l2_output_root: B256) -> String {
    let suffix = if risc0_zkvm::is_dev_mode() {
        "fake"
    } else {
        "zkp"
    };
    let prefix = B256::from(bytemuck::cast::<_, [u8; 32]>(KAILUA_FPVM_ID));
    format!("{prefix}-{l1_head}_{l2_output_root}.{suffix}",)
}
