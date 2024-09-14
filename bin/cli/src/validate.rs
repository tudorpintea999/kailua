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

use crate::channel::DuplexChannel;
use crate::propose::Proposal;
use crate::FAULT_PROOF_GAME_TYPE;
use alloy::network::{EthereumWallet, Network};
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, ReqwestProvider};
use alloy::signers::local::LocalSigner;
use alloy::transports::Transport;
use anyhow::{bail, Context};
use kailua_contracts::IDisputeGameFactory::{gameAtIndexReturn, IDisputeGameFactoryInstance};
use kailua_contracts::{FaultProofGame, IAnchorStateRegistry, IDisputeGameFactory};
use std::collections::HashMap;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio::{spawn, try_join};
use tracing::{debug, error, info, warn};

#[derive(clap::Args, Debug, Clone)]
pub struct ValidateArgs {
    #[arg(long, short, help = "Verbosity level (0-4)", action = clap::ArgAction::Count)]
    pub v: u8,

    /// Address of OP-NODE endpoint to use
    #[clap(long)]
    pub op_node_address: String,
    /// Address of L2 JSON-RPC endpoint to use (eth and debug namespace required).
    #[clap(long)]
    pub l2_node_address: String,
    /// Address of L1 JSON-RPC endpoint to use (eth namespace required)
    #[clap(long)]
    pub l1_node_address: String,
    /// Address of the L1 Beacon API endpoint to use.
    #[clap(long)]
    pub l1_beacon_address: Option<String>,

    /// Address of the L1 `AnchorStateRegistry` contract
    #[clap(long)]
    pub registry_contract: String,

    /// Secret key of L1 wallet to use for challenging and proving outputs
    #[clap(long)]
    pub validator_key: String,
}

pub async fn validate(args: ValidateArgs) -> anyhow::Result<()> {
    // initialize l2 connection
    let op_node_provider =
        ProviderBuilder::new().on_http(args.op_node_address.as_str().try_into()?);

    // initialize validator wallet
    info!("Initializing validator wallet.");
    let validator_signer = LocalSigner::from_str(&args.validator_key)?;
    let _validator_address = validator_signer.address();
    let validator_wallet = EthereumWallet::from(validator_signer);
    let validator_provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(validator_wallet)
            .on_http(args.l1_node_address.as_str().try_into()?),
    );
    // Init registry and factory contracts
    let anchor_state_registry = IAnchorStateRegistry::new(
        Address::from_str(&args.registry_contract)?,
        validator_provider.clone(),
    );
    info!("AnchorStateRegistry({:?})", anchor_state_registry.address());
    let dispute_game_factory = IDisputeGameFactory::new(
        anchor_state_registry.disputeGameFactory().call().await?._0,
        validator_provider.clone(),
    );
    info!("DisputeGameFactory({:?})", dispute_game_factory.address());
    let game_count: u64 = dispute_game_factory
        .gameCount()
        .call()
        .await?
        .gameCount_
        .to();
    info!("There have been {game_count} games created using DisputeGameFactory");
    let fault_proof_game_implementation = FaultProofGame::new(
        dispute_game_factory
            .gameImpls(FAULT_PROOF_GAME_TYPE)
            .call()
            .await?
            .impl_,
        validator_provider.clone(),
    );
    info!(
        "FaultProofGame({:?})",
        fault_proof_game_implementation.address()
    );
    if fault_proof_game_implementation.address().is_zero() {
        error!("Fault proof game is not installed!");
        exit(1);
    }
    // load constants
    let _max_proposal_span: u64 = fault_proof_game_implementation
        .maxBlockCount()
        .call()
        .await?
        .maxBlockCount_
        .to();
    let proposal_channel_pair = DuplexChannel::new_pair(4096);

    let handle_proposals = spawn(handle_proposals(
        proposal_channel_pair.1,
        dispute_game_factory,
        op_node_provider,
    ));

    let (proposals_task,) = try_join!(handle_proposals)?;
    proposals_task.context("handle_proposals")?;

    Ok(())
}

#[derive(Clone, Debug)]
pub enum Message {
    Proposal(Proposal),
    // todo: Proof
}

pub async fn handle_proposals<T: Transport + Clone, P: Provider<T, N>, N: Network>(
    _channel: DuplexChannel<Proposal>,
    dispute_game_factory: IDisputeGameFactoryInstance<T, P, N>,
    op_node_provider: ReqwestProvider,
) -> anyhow::Result<()> {
    let bond_value = dispute_game_factory
        .initBonds(FAULT_PROOF_GAME_TYPE)
        .call()
        .await?
        .bond_;
    // Initialize empty state
    info!("Initializing..");
    let mut proposal_tree: Vec<Proposal> = vec![];
    let mut proposal_index = HashMap::new();
    let mut search_start_index = 0;
    // Run the validator loop
    loop {
        // fetch latest games
        let game_count: u64 = dispute_game_factory
            .gameCount()
            .call()
            .await?
            .gameCount_
            .to();
        for factory_index in search_start_index..game_count {
            let gameAtIndexReturn {
                gameType_: game_type,
                proxy_: game_address,
                ..
            } = dispute_game_factory
                .gameAtIndex(U256::from(factory_index))
                .call()
                .await
                .context(format!("gameAtIndex {factory_index}/{game_count}"))?;
            // skip entries for other game types
            if game_type != FAULT_PROOF_GAME_TYPE {
                continue;
            }
            info!("Processing proposal at factory index {factory_index}");
            // Retrieve basic data
            let game_contract = FaultProofGame::new(game_address, dispute_game_factory.provider());
            let output_root = game_contract.rootClaim().call().await?.rootClaim_;
            let output_block_number = game_contract.l2BlockNumber().call().await?.l2BlockNumber_;
            let resolved = game_contract.resolvedAt().call().await?._0 > 0;
            let extra_data = game_contract.extraData().call().await?.extraData_;
            let local_index = proposal_tree.len();
            // Retrieve game/setup data
            let (parent_local_index, challenged, proven) = match extra_data.len() {
                0x10 => {
                    // FaultProofGame instance
                    let parent_factory_index = game_contract
                        .parentGameIndex()
                        .call()
                        .await?
                        .parentGameIndex_;
                    let Some(parent_local_index) = proposal_index.get(&parent_factory_index) else {
                        error!("SKIPPED: Could not find parent local index for game {game_address} at factory index {factory_index}.");
                        continue;
                    };
                    let challenged = game_contract.challengedAt().call().await?._0 > 0;
                    let proven = game_contract.provenAt().call().await?._0 > 0;
                    (*parent_local_index, challenged, proven)
                }
                0x20 => {
                    // FaultProofSetup instance
                    (local_index, false, false)
                }
                _ => bail!("Unexpected extra data length from game {game_address} at factory index {factory_index}")
            };
            // Decide correctness according to op-node
            let output_at_block: serde_json::Value = op_node_provider
                .client()
                .request(
                    "optimism_outputAtBlock",
                    (format!("0x{:x}", output_block_number),),
                )
                .await
                .context(format!("optimism_outputAtBlock {output_block_number}"))?;
            debug!("{:?}", &output_at_block);
            let local_output_root =
                FixedBytes::<32>::from_str(output_at_block["outputRoot"].as_str().unwrap())?;
            let correct = if local_output_root != output_root {
                // op-node disagrees, so this must be invalid
                warn!("Encountered an incorrect proposal {output_root} for block {output_block_number}! Expected {local_output_root}.");
                false
            } else if parent_local_index != local_index {
                // FaultProofGame can only be valid if parent is valid
                proposal_tree[parent_local_index].correct
            } else {
                // FaultProofSetup is self evident if op-node agrees
                true
            };
            // update local tree view
            proposal_index.insert(factory_index, local_index);
            info!("Read {correct} proposal at factory index {factory_index}");
            let output_block_number = output_block_number.to();
            proposal_tree.push(Proposal {
                factory_index,
                game_address,
                parent_local_index,
                output_root,
                output_block_number,
                challenged,
                proven,
                resolved,
                correct,
            });
            // todo: scan ancestry line and skip challenge if at least one invalid ancestor is challenged.
            if !correct && !challenged {
                // Issue challenge against incorrect unchallenged proposals
                game_contract
                    .challenge()
                    .value(bond_value / U256::from(2))
                    .send()
                    .await
                    .context("challenge (send)")?
                    .get_receipt()
                    .await
                    .context("challenge (get_receipt)")?;
                // todo: enqueue
            }
        }
        search_start_index = game_count;
        // todo: compute and publish proofs
        // priority goes to fault proofs for games where one is the challenger
        // secondary priority is validity proofs for mis-challenged games
        // this should happen on a separate task/thread to enable on-chain challenges to resume

        // Wait for new data
        sleep(Duration::from_secs(1)).await;
    }
}
