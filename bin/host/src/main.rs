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

use anyhow::Result;
use clap::Parser;
use kailua_client::fpvm_proof_file_name;
use kailua_common::BasicBootInfo;
use kailua_host::{aggregate_client_proofs, fetch_rollup_config, KailuaHostCli};
use kona_host::{init_tracing_subscriber, start_server_and_native_client};
use kona_primitives::RollupConfig;
use risc0_zkvm::Receipt;
use tempfile::tempdir;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::info;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let mut cfg = KailuaHostCli::parse();
    init_tracing_subscriber(cfg.kona.v)?;
    // generate a RollupConfig for the target network
    let tmp_dir = tempdir()?;
    if RollupConfig::from_l2_chain_id(cfg.kona.l2_chain_id).is_none()
        && cfg.kona.read_rollup_config().is_err()
    {
        info!("Fetching rollup config from nodes.");
        let tmp_cfg_file = tmp_dir.path().join("rollup-config.json");
        fetch_rollup_config(&cfg, &tmp_cfg_file).await?;
        cfg.kona.rollup_config_path = Some(tmp_cfg_file)
    }
    // generate a proof using the client and server for each block
    let mut receipts = Vec::<Receipt>::new();
    let mut chain = Vec::<BasicBootInfo>::new();
    loop {
        let mut instance_cfg = cfg.clone();
        if let Some(receipt) = receipts.last() {
            let last_instance_boot_info: BasicBootInfo = receipt.journal.decode()?;
            chain.push(last_instance_boot_info);
            instance_cfg.kona.l2_output_root = last_instance_boot_info.l2_claim;
            if last_instance_boot_info.l2_claim_block == cfg.kona.l2_block_number {
                // we've gathered all individual block proofs
                break;
            }
            info!(
                "Processing L2 Block Number: {} / {}",
                last_instance_boot_info.l2_claim_block, cfg.kona.l2_block_number
            );
        } else {
            info!("Processing first claim.");
        }
        // compute receipt if uncached
        let file_name =
            fpvm_proof_file_name(instance_cfg.kona.l1_head, instance_cfg.kona.l2_output_root);
        if File::open(file_name.clone()).await.is_err() {
            info!("Computing uncached receipt.");
            start_server_and_native_client(instance_cfg.kona.clone())
                .await
                .expect("Failed to execute");
        }
        // append receipt to vector
        let mut receipt_file = File::open(file_name.clone())
            .await
            .expect(&format!("Receipt not found in {file_name}."));
        let mut receipt_data = Vec::new();
        receipt_file.read_to_end(&mut receipt_data).await?;
        let receipt: Receipt = bincode::deserialize(&receipt_data)?;
        receipts.push(receipt);
    }

    // aggregate all proofs to form the final argument
    let _aggregate_proof = aggregate_client_proofs(
        BasicBootInfo {
            l1_head: cfg.kona.l1_head,
            l2_output_root: cfg.kona.l2_output_root,
            l2_claim: cfg.kona.l2_claim,
            l2_claim_block: cfg.kona.l2_block_number,
            chain_id: cfg.kona.l2_chain_id,
        },
        chain,
        receipts,
    )?;

    info!("Exiting host program.");
    Ok(())
}
