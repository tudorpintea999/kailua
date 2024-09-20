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

use crate::blob_provider::BlobProvider;
use crate::proposal::Proposal;
use crate::{hash_to_fe, output_at_block, FAULT_PROOF_GAME_TYPE};
use alloy::consensus::{Blob, BlobTransactionSidecar};
use alloy::network::{EthereumWallet, Network};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolValue;
use alloy::transports::Transport;
use anyhow::{bail, Context};
use kailua_common::intermediate_outputs;
use std::collections::{HashMap, HashSet};
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
    /// Address of the L1 Beacon API endpoint to use.
    #[clap(long)]
    pub l1_beacon_address: String,

    /// Address of the L1 `AnchorStateRegistry` contract
    #[clap(long)]
    pub registry_contract: String,

    /// Secret key of L1 wallet to use for proposing outputs
    #[clap(long)]
    pub proposer_key: String,
}

pub async fn propose(args: ProposeArgs) -> anyhow::Result<()> {
    // initialize blockchain connections
    let op_node_provider =
        ProviderBuilder::new().on_http(args.op_node_address.as_str().try_into()?);
    let cl_node_provider = BlobProvider::new(args.l1_beacon_address.as_str()).await?;

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
        // Wait for new data on every iteration
        sleep(Duration::from_secs(1)).await;
        // fetch latest games
        let game_count: u64 = dispute_game_factory
            .gameCount()
            .call()
            .await?
            .gameCount_
            .to();
        // Iterate over every new game and fetch its relevant values
        for factory_index in search_start_index..game_count {
            let kailua_contracts::IDisputeGameFactory::gameAtIndexReturn {
                gameType_: game_type,
                proxy_: game_address,
                timestamp_: created_at,
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
            let game_contract =
                kailua_contracts::FaultProofGame::new(game_address, &proposer_provider);
            let output_root = game_contract
                .rootClaim()
                .call()
                .await
                .context("rootClaim")?
                .rootClaim_;
            let output_block_number: u64 = game_contract
                .l2BlockNumber()
                .call()
                .await
                .context("l2BlockNumber")?
                .l2BlockNumber_
                .to();
            // Instantiate sub-claim trackers
            let mut challenged = HashSet::new();
            // let mut proven = HashMap::new();
            let mut resolved = HashSet::new();
            let extra_data = game_contract
                .extraData()
                .call()
                .await
                .context("extraData")?
                .extraData_;
            let local_index = proposal_tree.len();
            // Retrieve game/setup data
            let (parent_local_index, blob) = match extra_data.len() {
                0x30 => {
                    info!("Retrieving basic FaultProofGame proposal data");
                    // FaultProofGame instance
                    // check if game was resolved
                    if game_contract.resolvedAt().call().await.context("resolvedAt")?._0 > 0 {
                        resolved.insert(0);
                    }
                    // check if parent validity was challenged
                    if game_contract.challengedAt(0).call().await.context("challengedAt(0)")?._0 > 0 {
                        challenged.insert(0);
                    }
                    let parent_factory_index = game_contract
                        .parentGameIndex()
                        .call()
                        .await
                        .context("parentGameIndex")?
                        .parentGameIndex_;
                    let Some(parent_local_index) = proposal_index.get(&parent_factory_index) else {
                        error!("SKIPPED: Could not find parent local index for game {game_address} at factory index {factory_index}.");
                        continue;
                    };
                    let blob_hash = game_contract.proposalBlobHash().call().await.context("proposalBlobHash")?.blobHash_;
                    let blob = cl_node_provider.get_blob(
                        created_at,
                        blob_hash
                    ).await.context(format!("get_blob {created_at}/{blob_hash}"))?;
                    (*parent_local_index, Some(blob))
                }
                0x20 => {
                    info!("Retrieving basic FaultProofSetup proposal data");
                    // FaultProofSetup instance
                    (local_index, None)
                }
                len => bail!("Unexpected extra-data length {len} from game {game_address} at factory index {factory_index}")
            };
            // Get pointer to parent
            let parent = if parent_local_index != local_index {
                Some(&proposal_tree[parent_local_index])
            } else {
                None
            };
            // Decide correctness according to op-node
            info!("Deciding proposal validity.");
            let local_output_root = output_at_block(&op_node_provider, output_block_number).await?;
            // Parent must be correct if FaultProofGame and the local output must match the proposed output
            let is_correct_parent = parent.map(|p| p.is_correct()).unwrap_or(true);
            info!("Parent correctness: {is_correct_parent}");
            let game_correctness = local_output_root == output_root;
            info!("Main proposal correctness: {game_correctness}");
            // initialize correctness vector with game value at position 0
            let mut correct = vec![game_correctness];
            if let Some(parent) = parent {
                // Calculate intermediate correctness values for FaultProofGame
                let blob_data = blob.as_ref().expect("Missing blob data.");
                let starting_output_number = parent.output_block_number + 1;
                let num_intermediate = (output_block_number - starting_output_number) as usize;
                let outputs = intermediate_outputs(blob_data, num_intermediate)?;
                let mut bad_io = 0;
                for i in 0..num_intermediate {
                    let local_output =
                        output_at_block(&op_node_provider, starting_output_number + i as u64)
                            .await?;
                    let io_correct = hash_to_fe(local_output) == outputs[i];
                    correct.push(io_correct);
                    if !io_correct {
                        bad_io += 1;
                    }
                }
                if bad_io > 0 {
                    warn!("Found {bad_io} incorrect intermediate proposals.");
                } else {
                    info!("Intermediate proposals are correct.")
                }
            }
            // update local tree view
            info!("Storing proposal in memory.");
            proposal_index.insert(factory_index, local_index);
            proposal_tree.push(Proposal {
                factory_index,
                game_address,
                parent_local_index,
                intermediate_output_blob: blob,
                output_root,
                output_block_number,
                challenged,
                proven: HashMap::new(),
                resolved,
                correct,
                is_correct_parent,
            });
            let correct = proposal_tree[local_index].is_correct();
            info!("Read {correct} proposal at factory index {factory_index}");
            // Update canonical chain tip if this proposal yields a longer valid chain
            let canonical_tip_height = canonical_tip_index
                .map(|idx| proposal_tree[idx].output_block_number)
                .unwrap_or_default();
            if correct && output_block_number > canonical_tip_height {
                info!("Updating canonical proposal chain tip to local index {local_index}.");
                canonical_tip_index = Some(local_index);
            }
        }
        search_start_index = game_count;
        // Maintain the canonical proposal chain
        let Some(canonical_tip_index) = canonical_tip_index else {
            warn!("No canonical proposal tip known!");
            continue;
        };
        // Stack unresolved ancestors
        let mut unresolved_proposal_indices = vec![canonical_tip_index];
        loop {
            let local_index = *unresolved_proposal_indices.last().unwrap();
            let proposal = &proposal_tree[local_index];
            // break if we reach a resolved game or a setup game
            if proposal.is_game_resolved() {
                unresolved_proposal_indices.pop();
                break;
            } else if proposal.parent_local_index == local_index {
                // this is an unresolved setup game, keep in stack
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
        while let Some(local_index) = unresolved_proposal_indices.pop() {
            let local_proposal = &mut proposal_tree[local_index];
            let proposal_contract = kailua_contracts::FaultProofGame::new(
                local_proposal.game_address,
                &proposer_provider,
            );
            // Update on-chain resolution status
            if proposal_contract.resolvedAt().call().await?._0 > 0 {
                local_proposal.resolved.insert(0);
            }
            if local_proposal.is_game_resolved() {
                info!("Reached resolved ancestor proposal.");
                continue;
            }
            // Update on-chain challenged status
            if proposal_contract.challengedAt(0).call().await?._0 > 0 {
                local_proposal.challenged.insert(0);
            }
            if !local_proposal.is_game_challenged() {
                // Check for timeout
                let challenger_duration = proposal_contract
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
                resolve_game(proposal_contract).await?;
                continue;
            }
            // todo: fix logic below
            // Game is challenged, check proof status and resolve
            if proposal_contract.provenAt(0).call().await?._0 > 0 {
                let proof_status = proposal_contract
                    .proofStatus(0)
                    .call()
                    .await
                    .context("proofStatus()")?
                    ._0;
                local_proposal.proven.insert(0, proof_status == 2);
            }
            if local_proposal.is_game_proven().unwrap_or_default() {
                // resolve
                resolve_game(proposal_contract).await?;
            }
        }
        // Submit proposal to extend canonical chain
        let canonical_tip = &proposal_tree[canonical_tip_index];
        // Query op-node to get latest safe l2 head
        let sync_status: serde_json::Value = op_node_provider
            .client()
            .request_noparams("optimism_syncStatus")
            .await?;
        debug!("sync_status[safe_l2] {:?}", &sync_status["safe_l2"]);
        let output_block_number = sync_status["safe_l2"]["number"].as_u64().unwrap();
        let balance = proposer_provider.get_balance(proposer_address).await?;
        if balance < bond_value {
            error!("INSUFFICIENT BALANCE!");
            continue;
        } else if output_block_number < canonical_tip.output_block_number {
            warn!(
                "op-node is still {} blocks behind safe l2 head.",
                canonical_tip.output_block_number - output_block_number
            );
            continue;
        } else if output_block_number - canonical_tip.output_block_number < max_proposal_span {
            info!(
                "Waiting for safe l2 head to advance by {} more blocks before submitting proposal.",
                max_proposal_span - (output_block_number - canonical_tip.output_block_number)
            );
            continue;
        }
        // Prepare proposal
        let proposed_block_number = canonical_tip.output_block_number + max_proposal_span;
        let proposed_output_root =
            output_at_block(&op_node_provider, proposed_block_number).await?;
        // Prepare intermediate outputs
        let mut intermediate_outputs = vec![];
        let first_io_number = canonical_tip.output_block_number + 1;
        for i in first_io_number..proposed_block_number {
            let output = output_at_block(&op_node_provider, i).await?;
            intermediate_outputs.push(hash_to_fe(output));
        }
        let io_bytes = intermediate_outputs.concat();
        // Encode as blob sidecar
        let blob = Blob::right_padding_from(io_bytes.as_slice());
        let c_kzg_blob = c_kzg::Blob::from_bytes(blob.as_slice())?;
        let settings = alloy::consensus::EnvKzgSettings::default();
        let commitment = c_kzg::KzgCommitment::blob_to_kzg_commitment(&c_kzg_blob, settings.get())
            .expect("Failed to convert blob to commitment");
        let proof = c_kzg::KzgProof::compute_blob_kzg_proof(
            &c_kzg_blob,
            &commitment.to_bytes(),
            settings.get(),
        )?;

        // let z = c_kzg::Bytes32::new([0u8; 32]);
        // let (proof, value) = c_kzg::KzgProof::compute_kzg_proof(
        //     &c_kzg_blob,
        //     &z,
        //     settings.get()
        // )?;
        // let data = [
        //     alloy::eips::eip4844::kzg_to_versioned_hash(commitment.as_slice()).as_slice(),
        //     z.as_slice(),
        //     value.as_slice(),
        //     commitment.as_slice(),
        //     proof.as_slice()
        // ].concat();
        // info!("input: {}", hex::encode(&data));
        // exit(0);

        let sidecar = BlobTransactionSidecar::new(
            vec![blob],
            vec![commitment.to_bytes().into_inner().into()],
            vec![proof.to_bytes().into_inner().into()],
        );
        // compute extra data with block number, parent factory index, and blob hash
        let extra_data = [
            proposed_block_number.abi_encode_packed(),
            canonical_tip.factory_index.abi_encode_packed(),
            sidecar
                .versioned_hash_for_blob(0)
                .unwrap()
                .abi_encode_packed(),
        ]
        .concat();
        // Submit proposal
        info!("Proposing output {proposed_output_root} at {proposed_block_number}.");
        dispute_game_factory
            .create(
                FAULT_PROOF_GAME_TYPE,
                proposed_output_root,
                Bytes::from(extra_data),
            )
            .value(bond_value)
            .sidecar(sidecar)
            .send()
            .await
            .context("create FaultProofGame (send)")?
            .get_receipt()
            .await
            .context("create FaultProofGame (get_receipt)")?;
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
