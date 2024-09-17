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

use crate::fault::FaultArgs;
use crate::validate::ValidateArgs;
use alloy::contract::SolCallBuilder;
use alloy::network::{Network, TransactionBuilder};
use alloy::primitives::{Address, FixedBytes, Uint, U256};
use alloy::providers::{Provider, ReqwestProvider};
use alloy::transports::Transport;
use anyhow::Context;
use deploy::DeployArgs;
use kailua_contracts::Safe::SafeInstance;
use propose::ProposeArgs;
use std::str::FromStr;
use tracing::debug;

pub mod channel;
pub mod deploy;
pub mod fault;
pub mod propose;
pub mod validate;

pub const FAULT_PROOF_GAME_TYPE: u32 = 1337;

#[derive(clap::Parser, Debug, Clone)]
#[command(name = "kailua-cli")]
#[command(bin_name = "kailua-cli")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    Deploy(DeployArgs),
    Propose(ProposeArgs),
    Validate(ValidateArgs),
    TestFault(FaultArgs),
}

impl Cli {
    pub fn verbosity(&self) -> u8 {
        match self {
            Cli::Deploy(args) => args.v,
            Cli::Propose(args) => args.v,
            Cli::Validate(args) => args.v,
            Cli::TestFault(args) => args.propose_args.v,
        }
    }
}

pub async fn exec_safe_txn<
    T: Transport + Clone,
    P1: Provider<T, N>,
    P2: Provider<T, N>,
    C,
    N: Network,
>(
    txn: SolCallBuilder<T, P1, C, N>,
    safe: &SafeInstance<T, P2, N>,
    from: Address,
) -> anyhow::Result<()> {
    let req = txn.into_transaction_request();
    let value = req.value().unwrap_or_default();
    safe.execTransaction(
        req.to().unwrap(),
        value,
        req.input().cloned().unwrap_or_default(),
        0,
        Uint::from(req.gas_limit().unwrap_or_default()),
        U256::ZERO,
        U256::ZERO,
        Address::ZERO,
        Address::ZERO,
        [
            [0u8; 12].as_slice(),
            from.as_slice(),
            [0u8; 32].as_slice(),
            [1u8].as_slice(),
        ]
        .concat()
        .into(),
    )
    .send()
    .await?
    .get_receipt()
    .await?;
    Ok(())
}

pub async fn output_at_block(
    op_node_provider: &ReqwestProvider,
    output_block_number: u64,
) -> anyhow::Result<FixedBytes<32>> {
    let output_at_block: serde_json::Value = op_node_provider
        .client()
        .request(
            "optimism_outputAtBlock",
            (format!("0x{:x}", output_block_number),),
        )
        .await
        .context(format!("optimism_outputAtBlock {output_block_number}"))?;
    debug!("optimism_outputAtBlock {:?}", &output_at_block);
    Ok(FixedBytes::<32>::from_str(
        output_at_block["outputRoot"].as_str().unwrap(),
    )?)
}
