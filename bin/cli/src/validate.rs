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
use crate::channel::DuplexChannel;
use crate::proposal::Proposal;
use crate::{blob_fe_proof, block_hash, hash_to_fe, output_at_block, FAULT_PROOF_GAME_TYPE};
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::{ProviderBuilder};
use alloy::signers::local::LocalSigner;
use anyhow::{bail, Context};
use kailua_client::fpvm_proof_file_name;
use kailua_common::{intermediate_outputs, ProofJournal};
use kailua_contracts::IDisputeGameFactory::gameAtIndexReturn;
use kailua_contracts::{FaultProofGame, IAnchorStateRegistry, IDisputeGameFactory};
use kailua_host::fetch_rollup_config;
use risc0_zkvm::{InnerReceipt, MaybePruned, Receipt};
use std::collections::{HashMap, HashSet};
use std::env;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
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
    pub l1_beacon_address: String,

    /// Address of the L1 `AnchorStateRegistry` contract
    #[clap(long)]
    pub registry_contract: String,

    /// Secret key of L1 wallet to use for challenging and proving outputs
    #[clap(long)]
    pub validator_key: String,
}

pub async fn validate(args: ValidateArgs) -> anyhow::Result<()> {
    // We run two concurrent tasks, one for the chain, and one for the prover.
    // Both tasks communicate using the duplex channel
    let channel_pair = DuplexChannel::new_pair(4096);

    let handle_proposals = spawn(handle_proposals(channel_pair.0, args.clone()));
    let handle_proofs = spawn(handle_proofs(channel_pair.1, args));

    let (proposals_task, proofs_task) = try_join!(handle_proposals, handle_proofs)?;
    proposals_task.context("handle_proposals")?;
    proofs_task.context("handle_proofs")?;

    Ok(())
}

#[derive(Clone, Debug)]
pub enum Message {
    // The proposal and its parent
    Proposal {
        local_index: usize,
        l1_head: FixedBytes<32>,
        l2_head: FixedBytes<32>,
        l2_output_root: FixedBytes<32>,
        l2_block_number: u64,
        l2_claim: FixedBytes<32>,
    },
    Proof(usize, Receipt),
}

pub async fn handle_proofs(
    mut channel: DuplexChannel<Message>,
    args: ValidateArgs,
) -> anyhow::Result<()> {
    // Fetch rollup configuration
    let l2_chain_id = fetch_rollup_config(&args.op_node_address, &args.l2_node_address, None)
        .await?
        .l2_chain_id
        .to_string();
    // Read executable paths from env vars
    let kailua_host = env::var("KAILUA_HOST").unwrap_or_else(|_| {
        warn!("KAILUA_HOST set to default ./target/debug/kailua-host");
        String::from("./target/debug/kailua-host")
    });
    let kailua_client = env::var("KAILUA_CLIENT").unwrap_or_else(|_| {
        warn!("KAILUA_CLIENT set to default ./target/debug/kailua-client");
        String::from("./target/debug/kailua-client")
    });
    let data_dir = env::var("KAILUA_DATA").unwrap_or_else(|_| {
        warn!("KAILUA_DATA set to default .localtestdata");
        String::from(".localtestdata")
    });
    // Run proof generator loop
    loop {
        // Dequeue messages
        // todo: priority goes to fault proofs for games where one is the challenger
        // todo: secondary priority is validity proofs for mis-challenged games
        let Message::Proposal {
            local_index,
            l1_head,
            l2_head,
            l2_output_root,
            l2_block_number,
            l2_claim,
        } = channel
            .receiver
            .recv()
            .await
            .expect("proof receiver channel closed")
        else {
            bail!("Unexpected message type.");
        };
        info!("Processing proof for local index {local_index}.");
        // Prepare kailua-host parameters
        let proof_file_name = fpvm_proof_file_name(l1_head, l2_claim, l2_output_root);
        let l1_head = l1_head.to_string();
        let l2_head = l2_head.to_string();
        let l2_output_root = l2_output_root.to_string();
        let l2_claim = l2_claim.to_string();
        let l2_block_number = l2_block_number.to_string();
        let verbosity = [
            String::from("-"),
            (0..args.v).map(|_| 'v').collect::<String>(),
        ]
        .concat();
        let mut proving_args = vec![
            "--l1-head", // l1 head from on-chain proposal
            &l1_head,
            "--l2-head", // l2 starting block hash from on-chain proposal
            &l2_head,
            "--l2-output-root", // l2 starting output root
            &l2_output_root,
            "--l2-claim", // proposed output root
            &l2_claim,
            "--l2-block-number", // proposed block number
            &l2_block_number,
            "--l2-chain-id", // rollup chain id
            &l2_chain_id,
            "--l1-node-address", // l1 el node
            &args.l1_node_address,
            "--l1-beacon-address", // l1 cl node
            &args.l1_beacon_address,
            "--l2-node-address", // l2 el node
            &args.l2_node_address,
            "--op-node-address", // l2 cl node
            &args.op_node_address,
            "--exec", // path to kailua-client
            &kailua_client,
            "--data-dir", // path to cache
            &data_dir,
        ];
        // verbosity level
        if args.v > 0 {
            proving_args.push(&verbosity);
        }
        // Prove via kailua-host (re dev mode/bonsai: env vars inherited!)
        let mut kailua_host_command = Command::new(&kailua_host);
        // get fake receipts when building under devnet
        #[cfg(feature = "devnet")]
        kailua_host_command.env("RISC0_DEV_MODE", "1");
        // pass arguments to point at target block
        kailua_host_command.args(proving_args);
        debug!("kailua_host_command {:?}", &kailua_host_command);
        {
            let proving_task = kailua_host_command
                .kill_on_drop(true)
                .spawn()
                .context("Invoking kailua-host")?
                .wait()
                // .output()
                .await?;
            if !proving_task.success() {
                error!("Proving task failure.");
            } else {
                info!("Proving task successful.");
            }
        }
        sleep(Duration::from_secs(1)).await;
        // Read receipt file
        let mut receipt_file = File::open(proof_file_name.clone()).await?;
        info!("Opened receipt file {proof_file_name}.");
        let mut receipt_data = Vec::new();
        receipt_file.read_to_end(&mut receipt_data).await?;
        info!("Read entire receipt file.");
        let receipt: Receipt = bincode::deserialize(&receipt_data)?;
        // Send proof via the channel
        channel
            .sender
            .send(Message::Proof(local_index, receipt))
            .await?;
        info!("Proof for local index {local_index} complete.");
    }
}

pub async fn handle_proposals(
    mut channel: DuplexChannel<Message>,
    args: ValidateArgs,
) -> anyhow::Result<()> {
    // initialize blockchain connections
    let op_node_provider =
        ProviderBuilder::new().on_http(args.op_node_address.as_str().try_into()?);
    let l2_node_provider =
        ProviderBuilder::new().on_http(args.l2_node_address.as_str().try_into()?);
    let cl_node_provider = BlobProvider::new(args.l1_beacon_address.as_str()).await?;

    // initialize validator wallet
    info!("Initializing validator wallet.");
    let validator_signer = LocalSigner::from_str(&args.validator_key)?;
    let validator_address = validator_signer.address();
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
        // Wait for new data on every iteration
        sleep(Duration::from_secs(1)).await;
        // validate latest games
        // todo: preform validations based on l1_head
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
            let game_contract = FaultProofGame::new(game_address, dispute_game_factory.provider());
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
            // let resolved = game_contract.resolvedAt().call().await?._0 > 0;
            let extra_data = game_contract.extraData().call().await?.extraData_;
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
            let game_correctness = is_correct_parent && local_output_root == output_root;
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
                    let mut local_output =
                        output_at_block(&op_node_provider, starting_output_number + i as u64)
                            .await?;
                    local_output.0[0] = 0;
                    let io_correct = local_output == outputs[i];
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
            // Validate
            let local_proposal = &mut proposal_tree[local_index];
            let correct = local_proposal.is_correct();
            info!("Read {correct} proposal at factory index {factory_index}");
            if correct {
                continue;
            }
            // Issue possible challenge
            let challenged_position = if !local_proposal.is_correct_parent {
                // challenge based on expected parent resolution in favor of challenger
                0u32
            } else {
                // an output must be challenged and proven incorrect
                local_proposal
                    .correct
                    .iter()
                    // skip the first flag which denotes invalid root claim
                    .skip(1)
                    .position(|v| !v)
                    .map(|p| p + 1)
                    .unwrap_or(local_proposal.correct.len()) as u32
            };
            // query for on-chain challenge status
            if game_contract
                .challengedAt(challenged_position)
                .call()
                .await
                .context(format!("challengedAt({challenged_position})"))?
                ._0
                > 0
            {
                local_proposal.challenged.insert(challenged_position);
            }
            // issue challenge if needed
            if !local_proposal.is_output_challenged(challenged_position) {
                info!("Issuing challenge against position {challenged_position}.");
                game_contract
                    .challenge(challenged_position)
                    .value(bond_value / U256::from(2))
                    .send()
                    .await
                    .context(format!("challenge({challenged_position}) (send)"))?
                    .get_receipt()
                    .await
                    .context(format!("challenge({challenged_position}) (get_receipt)"))?;
            }
            // check challenger
            if game_contract
                .challenger(challenged_position)
                .call()
                .await?
                ._0
                != validator_address
            {
                info!("{correct} proposal at factory index {factory_index} was challenged by another validator.");
                continue;
            }
            // query for on-chain proof status
            let proof_status = game_contract
                .provenAt(challenged_position)
                .call()
                .await
                .context(format!("provenAt({challenged_position})"))?
                ._0;
            if proof_status > 0 {
                local_proposal
                    .proven
                    .insert(challenged_position, proof_status == 2);
            }
            // if the challenged output is unproven, enqueue a proving task
            if challenged_position != 0
                && local_proposal
                    .is_output_proven(challenged_position)
                    .is_none()
            {
                // Read additional data for Kona invocation
                info!("Requesting proof for local index {local_index}.");
                let l1_head = game_contract
                    .l1Head()
                    .call()
                    .await
                    .context("l1Head")?
                    .l1Head_;
                debug!("l1_head {:?}", &l1_head);
                let l2_head_number = game_contract
                    .startingBlockNumber()
                    .call()
                    .await
                    .context("startingBlockNumber")?
                    .startingBlockNumber_
                    .to::<u64>()
                    + challenged_position as u64
                    - 1;
                debug!("l2_head_number {:?}", &l2_head_number);
                let l2_head = block_hash(&l2_node_provider, l2_head_number)
                    .await
                    .context("block_hash")?;
                debug!("l2_head {:?}", &l2_head);
                let l2_output_root = output_at_block(&op_node_provider, l2_head_number)
                    .await
                    .context("output_at_block")?;
                let l2_block_number = l2_head_number + 1;
                let l2_claim = output_at_block(&op_node_provider, l2_block_number)
                    .await
                    .context("output_at_block")?;
                // Message proving task
                channel
                    .sender
                    .send(Message::Proposal {
                        local_index,
                        l1_head,
                        l2_head,
                        l2_output_root,
                        l2_block_number,
                        l2_claim,
                    })
                    .await?;
            }
            // todo: validity proving
            info!("Validated {correct} proposal at factory index {factory_index}.");
        }
        search_start_index = game_count;
        // publish computed proofs and resolve games
        while !channel.receiver.is_empty() {
            let Message::Proof(local_index, receipt) = channel
                .receiver
                .recv()
                .await
                .expect("proposals receiver channel closed")
            else {
                bail!("Unexpected message type.");
            };
            let proposal = &proposal_tree[local_index];
            let proposal_parent = &proposal_tree[proposal.parent_local_index];
            let game_contract =
                FaultProofGame::new(proposal.game_address, dispute_game_factory.provider());
            let proof_journal = ProofJournal::decode_packed(receipt.journal.as_ref())?;
            let io_blob = proposal
                .intermediate_output_blob
                .clone()
                .expect("Missing blob data.");
            let proposal_span = (proposal.output_block_number - proposal_parent.output_block_number) as u32;
            let challenge_position =
                (proof_journal.l2_claim_block - proposal_parent.output_block_number) as u32;
            let io_hashes = intermediate_outputs(&io_blob, proposal_span as usize)?;
            let challenged_output = io_hashes
                .get(challenge_position as usize - 1)
                .copied()
                .unwrap_or(proposal.output_root);
            let is_fault_proof =
                hash_to_fe(proof_journal.l2_claim) != hash_to_fe(challenged_output);
            let proof_label = if is_fault_proof { "fault" } else { "validity" };
            info!(
                "Utilizing {proof_label} proof in game at {}",
                proposal.game_address
            );
            // todo: // warn if the receipt journal is invalid
            // let expected_journal_bytes =
            //     derive_expected_journal(&game_contract, is_fault_proof).await?;
            // if receipt.journal.bytes != expected_journal_bytes {
            //     error!("Receipt journal does not match journal expected by game contract.");
            // } else {
            //     info!("Receipt journal validated.");
            // }
            // patch the receipt image id if in dev mode
            let expected_image_id = game_contract.imageId().call().await?.imageId_.0;
            #[cfg(feature = "devnet")]
            let receipt = {
                let mut receipt = receipt;
                let InnerReceipt::Fake(fake_inner_receipt) = &mut receipt.inner else {
                    bail!("Found real receipt under devmode");
                };
                let MaybePruned::Value(claim) = &mut fake_inner_receipt.claim else {
                    bail!("Fake receipt claim is pruned.");
                };
                warn!("DEVNET-ONLY: Patching fake receipt image id to match game contract.");
                claim.pre = MaybePruned::Pruned(expected_image_id.into());
                receipt
            };
            // verify that the receipt is valid
            if receipt.verify(expected_image_id).is_err() {
                error!("Could not verify receipt against image id in contract.");
            } else {
                info!("Receipt validated.");
            }
            // only prove unproven games
            let proof_status = game_contract
                .proofStatus(challenge_position)
                .call()
                .await
                .context(format!("proofStatus({challenge_position})"))?
                ._0;
            if proof_status == 0 {
                let encoded_seal = risc0_ethereum_contracts::encode_seal(&receipt)?;
                let mut proofs = vec![];
                if challenge_position > 1 {
                    let (proof, _) = blob_fe_proof(&io_blob.blob, challenge_position as usize - 2)?;
                    proofs.push(Bytes::from(proof.to_vec()));
                }
                if challenge_position < proposal_span {
                    let (proof, _) = blob_fe_proof(&io_blob.blob, challenge_position as usize - 1)?;
                    proofs.push(Bytes::from(proof.to_vec()));
                }

                info!("Submitting proof {}.", hex::encode(&encoded_seal));
                game_contract
                    .prove(
                        challenge_position,
                        encoded_seal.into(),
                        proof_journal.l2_output_root,
                        challenged_output,
                        proof_journal.l2_claim,
                        Bytes::from(io_blob.kzg_commitment.to_vec()),
                        proofs,
                    )
                    .send()
                    .await
                    .context("prove (send)")?
                    .get_receipt()
                    .await
                    .context("prove (get_receipt)")?;
                info!("Resolving outout {challenge_position}.");
                game_contract
                    .resolveClaim(challenge_position)
                    .send()
                    .await
                    .context("resolveClaim (send)")?
                    .get_receipt()
                    .await
                    .context("resolveClaim (get_receipt)")?;
                let resolution = game_contract.status().call().await?.status_;
                info!("Game resolved: {resolution}");
            } else {
                warn!("Skipping proof submission for already proven game at local index {local_index}.");
            }
        }
    }
}
