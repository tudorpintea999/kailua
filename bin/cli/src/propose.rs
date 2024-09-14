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

use crate::FAULT_PROOF_GAME_TYPE;
use alloy::network::{EthereumWallet, Network};
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolValue;
use alloy::transports::Transport;
use anyhow::{bail, Context};
use kailua_contracts::IDisputeGameFactory::gameAtIndexReturn;
use std::collections::HashMap;
use std::process::exit;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

#[derive(clap::Args, Debug, Clone)]
pub struct ProposeArgs {
    #[arg(long, short, help = "Verbosity level (0-4)", action = clap::ArgAction::Count)]
    pub v: u8,

    /// Address of OP-NODE endpoint to use
    #[clap(long)]
    pub op_node_address: String,
    /// Address of L1 JSON-RPC endpoint to use (eth namespace required)
    #[clap(long)]
    pub l1_node_address: String,

    /// Address of the L1 `AnchorStateRegistry` contract
    #[clap(long)]
    pub registry_contract: String,

    /// Secret key of L1 wallet to use for proposing outputs
    #[clap(long)]
    pub proposer_key: String,
}

#[derive(Clone, Debug, Copy)]
pub struct Proposal {
    pub factory_index: u64,
    pub game_address: Address,
    pub parent_local_index: usize,
    pub output_root: FixedBytes<32>,
    pub output_block_number: u64,
    pub challenged: bool,
    pub proven: bool,
    pub resolved: bool,
    pub correct: bool,
}

pub async fn propose(args: ProposeArgs) -> anyhow::Result<()> {
    // initialize l2 connection
    let op_node_provider =
        ProviderBuilder::new().on_http(args.op_node_address.as_str().try_into()?);

    // initialize proposer wallet
    info!("Initializing proposer wallet.");
    let proposer_signer = LocalSigner::from_str(&args.proposer_key)?;
    let proposer_address = proposer_signer.address();
    let proposer_wallet = EthereumWallet::from(proposer_signer);
    let proposer_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(&proposer_wallet)
        .on_http(args.l1_node_address.as_str().try_into()?);
    // Init registry and factory contracts
    let anchor_state_registry = kailua_contracts::IAnchorStateRegistry::new(
        Address::from_str(&args.registry_contract)?,
        &proposer_provider,
    );
    info!("AnchorStateRegistry({:?})", anchor_state_registry.address());
    let dispute_game_factory = kailua_contracts::IDisputeGameFactory::new(
        anchor_state_registry.disputeGameFactory().call().await?._0,
        &proposer_provider,
    );
    info!("DisputeGameFactory({:?})", dispute_game_factory.address());
    let game_count: u64 = dispute_game_factory
        .gameCount()
        .call()
        .await?
        .gameCount_
        .to();
    info!("There have been {game_count} games created using DisputeGameFactory");
    let fault_proof_game_implementation = kailua_contracts::FaultProofGame::new(
        dispute_game_factory
            .gameImpls(FAULT_PROOF_GAME_TYPE)
            .call()
            .await?
            .impl_,
        &proposer_provider,
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
    let max_proposal_span: u64 = fault_proof_game_implementation
        .maxBlockCount()
        .call()
        .await?
        .maxBlockCount_
        .to();
    let max_clock_duration = fault_proof_game_implementation
        .maxClockDuration()
        .call()
        .await?
        .maxClockDuration_;
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
    let mut canonical_tip_index: Option<usize> = None;
    // Run the proposer loop
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
                // sanity check
                let game_contract =
                    kailua_contracts::FaultProofGame::new(game_address, &proposer_provider);
                let output_root = game_contract.rootClaim().call().await?.rootClaim_;
                let output_block_number =
                    game_contract.l2BlockNumber().call().await?.l2BlockNumber_;
                let output_at_block: serde_json::Value = op_node_provider
                    .client()
                    .request(
                        "optimism_outputAtBlock",
                        (format!("0x{:x}", output_block_number),),
                    )
                    .await
                    .context(format!("optimism_outputAtBlock {output_block_number}"))?;
                let local_output_root =
                    FixedBytes::<32>::from_str(output_at_block["outputRoot"].as_str().unwrap())?;
                if local_output_root != output_root {
                    warn!("Encountered a bad proposal of height {output_block_number} under game type {game_type}.");
                };
                continue;
            }
            info!("Processing proposal at factory index {factory_index}");
            // Retrieve basic data
            let game_contract =
                kailua_contracts::FaultProofGame::new(game_address, &proposer_provider);
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
            // Update canonical chain tip if this proposal yields a longer valid chain
            let canonical_tip_height = canonical_tip_index
                .map(|idx| proposal_tree[idx].output_block_number)
                .unwrap_or_default();
            if correct && output_block_number > canonical_tip_height {
                canonical_tip_index = Some(local_index);
            }
        }
        search_start_index = game_count;
        // Maintain the canonical proposal chain
        if let Some(canonical_tip_index) = canonical_tip_index {
            // Queue unresolved ancestors
            let mut unresolved_proposal_indices = vec![canonical_tip_index];
            loop {
                let local_index = *unresolved_proposal_indices.last().unwrap();
                let proposal = &proposal_tree[local_index];
                // break if we reach a resolved game or a setup game
                if proposal.resolved {
                    unresolved_proposal_indices.pop();
                    break;
                } else if proposal.parent_local_index == local_index {
                    break;
                }
                unresolved_proposal_indices.push(proposal.parent_local_index);
            }
            // Resolve in reverse order
            if !unresolved_proposal_indices.is_empty() {
                info!(
                    "Attempting to resolve {} ancestors.",
                    unresolved_proposal_indices.len()
                );
            }
            for local_index in unresolved_proposal_indices.iter().rev() {
                let unresolved_proposal = &mut proposal_tree[*local_index];
                let game_contract = kailua_contracts::FaultProofGame::new(
                    unresolved_proposal.game_address,
                    &proposer_provider,
                );
                unresolved_proposal.resolved = game_contract.resolvedAt().call().await?._0 > 0;
                if unresolved_proposal.resolved {
                    info!("Reached resolved ancestor proposal.");
                    continue;
                }
                unresolved_proposal.challenged = game_contract.challengedAt().call().await?._0 > 0;
                if !unresolved_proposal.challenged {
                    // Check for timeout
                    let challenger_duration = game_contract
                        .getChallengerDuration()
                        .call()
                        .await?
                        .duration_;
                    if challenger_duration < max_clock_duration {
                        info!(
                            "Waiting for {} more seconds before resolution.",
                            max_clock_duration - challenger_duration
                        );
                        break;
                    }
                    resolve_game(game_contract).await?;
                    continue;
                }
                unresolved_proposal.proven = game_contract.provenAt().call().await?._0 > 0;
                if unresolved_proposal.proven {
                    // resolve
                    resolve_game(game_contract).await?;
                }
            }
            // Submit proposal to extend canonical chain
            let canonical_tip = &proposal_tree[canonical_tip_index];
            // Query op-node to get latest safe l2 head
            let sync_status: serde_json::Value = op_node_provider
                .client()
                .request_noparams("optimism_syncStatus")
                .await?;
            debug!("{:?}", &sync_status["safe_l2"]);
            let output_block_number = sync_status["safe_l2"]["number"].as_u64().unwrap();
            let balance = proposer_provider.get_balance(proposer_address).await?;
            if balance < bond_value {
                error!("INSUFFICIENT BALANCE!");
            } else if output_block_number < canonical_tip.output_block_number {
                warn!(
                    "op-node is still {} blocks behind safe l2 head.",
                    canonical_tip.output_block_number - output_block_number
                );
            } else if output_block_number - canonical_tip.output_block_number < max_proposal_span {
                info!(
                    "Waiting for safe l2 head to advance by {} more blocks before submitting proposal.",
                    max_proposal_span - (output_block_number - canonical_tip.output_block_number)
                );
            } else {
                let proposed_block_number = canonical_tip.output_block_number + max_proposal_span;
                let output_at_block: serde_json::Value = op_node_provider
                    .client()
                    .request(
                        "optimism_outputAtBlock",
                        (format!("0x{:x}", proposed_block_number),),
                    )
                    .await?;
                debug!("{:?}", &output_at_block);
                let root_claim =
                    FixedBytes::<32>::from_str(output_at_block["outputRoot"].as_str().unwrap())?;
                info!("Proposing output {root_claim} at {proposed_block_number}.");
                let extra_data = [
                    proposed_block_number.abi_encode_packed(),
                    canonical_tip.factory_index.abi_encode_packed(),
                ]
                .concat();
                dispute_game_factory
                    .create(FAULT_PROOF_GAME_TYPE, root_claim, Bytes::from(extra_data))
                    .value(bond_value)
                    .send()
                    .await
                    .context("create FaultProofGame (send)")?
                    .get_receipt()
                    .await
                    .context("create FaultProofGame (get_receipt)")?;
            }
        } else {
            warn!("No canonical proposal tip known")
        }
        // Wait for new data
        sleep(Duration::from_secs(1)).await;
    }
}

pub async fn resolve_game<T: Transport + Clone, P: Provider<T, N>, N: Network>(
    game: kailua_contracts::FaultProofGame::FaultProofGameInstance<T, P, N>,
) -> anyhow::Result<N::ReceiptResponse> {
    info!("Resolving game.");
    Ok(game
        .resolve()
        .send()
        .await
        .context("FaultProofSetup::resolve (send)")?
        .get_receipt()
        .await
        .context("FaultProofSetup::resolve (get_receipt)")?)
}
