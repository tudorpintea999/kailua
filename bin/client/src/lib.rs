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

pub mod oracle;

use crate::oracle::{HINT_WRITER, ORACLE_READER};
use alloy_primitives::{keccak256, B256};
use anyhow::Context;
use kailua_build::{KAILUA_FPVM_ELF, KAILUA_FPVM_ID};
use kailua_common::oracle::{FPVM_GET_PREIMAGE, FPVM_WRITE_HINT, ORACLE_LRU_SIZE};
use kona_client::l1::OracleBlobProvider;
use kona_client::{BootInfo, CachingOracle};
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::sync::Arc;
use tokio::join;
use tokio::runtime::Handle;
use tokio::task::spawn_blocking;
use tracing::info;

pub async fn run_native_client() -> anyhow::Result<Option<B256>> {
    info!("Preamble");
    let oracle = Arc::new(CachingOracle::new(
        ORACLE_LRU_SIZE,
        ORACLE_READER,
        HINT_WRITER,
    ));

    let boot = Arc::new(
        BootInfo::load(oracle.as_ref())
            .await
            .context("BootInfo::load")?,
    );
    let beacon = OracleBlobProvider::new(oracle.clone());
    kailua_common::client::run_client(oracle, boot, beacon)
}

pub async fn prove_zkvm_client() -> anyhow::Result<Receipt> {
    let client_task = spawn_blocking(|| {
        let oracle = Arc::new(CachingOracle::new(
            ORACLE_LRU_SIZE,
            ORACLE_READER,
            HINT_WRITER,
        ));
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
        let prove_info = prover.prove_with_opts(env, KAILUA_FPVM_ELF, &ProverOpts::groth16())?;
        println!(
            "Proof of {} total cycles ({} user cycles) computed.",
            prove_info.stats.total_cycles, prove_info.stats.user_cycles
        );
        prove_info
            .receipt
            .verify(KAILUA_FPVM_ID)
            .context("receipt verification")?;
        Ok::<_, anyhow::Error>(prove_info.receipt)
    });
    join!(client_task).0?
}

pub fn fpvm_proof_file_name(l1_head: B256, l2_claim: B256, l2_output_root: B256) -> String {
    let version = risc0_zkvm::get_version().unwrap();
    let suffix = if risc0_zkvm::is_dev_mode() {
        "fake"
    } else {
        "zkp"
    };
    let data = [
        bytemuck::cast::<_, [u8; 32]>(KAILUA_FPVM_ID).as_slice(),
        l1_head.as_slice(),
        l2_output_root.as_slice(),
        l2_claim.as_slice()
    ].concat();
    let file_name = keccak256(data);
    format!(
        "risc0-{}-{file_name}.{suffix}",
        version.to_string()
    )
}
