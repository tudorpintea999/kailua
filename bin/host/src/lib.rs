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

use alloy_provider::{Provider, ProviderBuilder};
use clap::Parser;
use kailua_build::{KAILUA_FPVM_CHAINED_ELF, KAILUA_FPVM_ID};
use kailua_common::BasicBootInfo;
use kona_primitives::RollupConfig;
use risc0_zkvm::{default_prover, AssumptionReceipt, ExecutorEnv, ProverOpts, Receipt};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::fs;

// #[derive(clap::Parser, Debug, Clone)]
// #[command(name = "kailua")]
// #[command(bin_name = "kailua")]
// pub enum KailuaCli {
//     Prove(KailuaHostCli)
// }

/// The host binary CLI application arguments.
#[derive(Parser, Serialize, Clone, Debug)]
pub struct KailuaHostCli {
    #[clap(flatten)]
    pub kona: kona_host::HostCli,

    /// Address of OP-NODE endpoint to use
    #[clap(long)]
    pub op_node_address: Option<String>,
}

pub fn aggregate_client_proofs(
    claim: BasicBootInfo,
    chain: Vec<BasicBootInfo>,
    receipts: Vec<Receipt>,
) -> anyhow::Result<Receipt> {
    let env = {
        let mut builder = ExecutorEnv::builder();
        builder
            .write(&KAILUA_FPVM_ID)?
            .write(&claim)?
            .write(&chain)?;
        for receipt in receipts {
            builder.add_assumption(AssumptionReceipt::from(receipt));
        }
        builder.build()?
    };
    let prover = default_prover();
    let prove_info =
        prover.prove_with_opts(env, KAILUA_FPVM_CHAINED_ELF, &ProverOpts::succinct())?;

    println!(
        "STARK proof of {} total cycles ({} user cycles) computed.",
        prove_info.stats.total_cycles, prove_info.stats.user_cycles
    );

    Ok(prove_info.receipt)
}

pub async fn fetch_rollup_config(
    op_node_address: &str,
    l2_node_address: &str,
    json_file_path: Option<&PathBuf>,
) -> anyhow::Result<RollupConfig> {
    let op_node_provider = ProviderBuilder::new().on_http(op_node_address.try_into()?);
    let l2_node_provider = ProviderBuilder::new().on_http(l2_node_address.try_into()?);

    let mut rollup_config: Value = op_node_provider
        .client()
        .request_noparams("optimism_rollupConfig")
        .await?;
    let chain_config: Value = l2_node_provider
        .client()
        .request_noparams("debug_chainConfig")
        .await?;

    // genesis
    rollup_config["genesis"]["L1"] = rollup_config["genesis"]
        .as_object_mut()
        .unwrap()
        .remove("l1")
        .unwrap();
    rollup_config["genesis"]["L1"]["Hash"] = rollup_config["genesis"]["L1"]
        .as_object_mut()
        .unwrap()
        .remove("hash")
        .unwrap();
    rollup_config["genesis"]["L1"]["Number"] = rollup_config["genesis"]["L1"]
        .as_object_mut()
        .unwrap()
        .remove("number")
        .unwrap();
    rollup_config["genesis"]["L2"] = rollup_config["genesis"]
        .as_object_mut()
        .unwrap()
        .remove("l2")
        .unwrap();
    rollup_config["genesis"]["L2"]["Hash"] = rollup_config["genesis"]["L2"]
        .as_object_mut()
        .unwrap()
        .remove("hash")
        .unwrap();
    rollup_config["genesis"]["L2"]["Number"] = rollup_config["genesis"]["L2"]
        .as_object_mut()
        .unwrap()
        .remove("number")
        .unwrap();
    // base_fee_params
    rollup_config["base_fee_params"] = json!({
        "elasticity_multiplier": chain_config["optimism"]["eip1559Elasticity"]
        .as_u64()
        .unwrap(),
        "max_change_denominator": chain_config["optimism"]["eip1559Denominator"]
        .as_u64()
        .unwrap()
    });
    // canyon_base_fee_params
    if let Some(canyon_denominator) = chain_config["optimism"]["eip1559DenominatorCanyon"].as_u64()
    {
        rollup_config["canyon_base_fee_params"] = json!({
            "elasticity_multiplier": chain_config["optimism"]["eip1559Elasticity"]
        .as_u64()
        .unwrap(),
            "max_change_denominator": canyon_denominator
        });
    }
    // fork times
    for fork in &[
        "regolithTime",
        "canyonTime",
        "deltaTime",
        "ecotoneTime",
        "fjordTime",
        "graniteTime",
        "holoceneTime",
    ] {
        if let Some(value) = chain_config[fork].as_str() {
            rollup_config[fork] = json!(value);
        }
    }
    // export
    // dbg!(&rollup_config);
    let ser_config = serde_json::to_string(&rollup_config)?;
    if let Some(json_file_path) = json_file_path {
        fs::write(json_file_path, &ser_config).await?;
    }

    Ok(serde_json::from_str(&ser_config)?)
}
