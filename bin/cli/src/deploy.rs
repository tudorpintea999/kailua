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

use alloy::network::{EthereumWallet, TxSigner};
use alloy::primitives::{Address, Bytes, Uint, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolValue;
use anyhow::Context;
use kailua_build::KAILUA_FPVM_CHAINED_ID;
use kailua_common::config_hash;
use kailua_host::fetch_rollup_config;
use std::process::exit;
use std::str::FromStr;
use tracing::{debug, error, info};

#[derive(clap::Args, Debug, Clone)]
pub struct DeployArgs {
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
    /// Address of the L1 `OptimismPortal` contract
    #[clap(long)]
    pub portal_contract: String,

    /// Secret key of L1 wallet to use for deploying contracts
    #[clap(long)]
    pub deployer_key: String,
    /// Secret key of L1 wallet that (indirectly) owns `DisputeGameFactory`
    #[clap(long)]
    pub owner_key: String,
    /// Secret key of L1 guardian wallet
    #[clap(long)]
    pub guardian_key: String,
}

pub async fn deploy(args: DeployArgs) -> anyhow::Result<()> {
    // initialize guardian wallet
    info!("Initializing guardian wallet.");
    let guardian_signer = LocalSigner::from_str(&args.guardian_key)?;
    let guardian_address = guardian_signer.address();
    let guardian_wallet = EthereumWallet::from(guardian_signer);
    let guardian_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(&guardian_wallet)
        .on_http(args.l1_node_address.as_str().try_into()?);
    let optimism_portal = kailua_contracts::OptimismPortal::new(
        Address::from_str(&args.portal_contract)?,
        &guardian_provider,
    );
    let portal_guardian_address = optimism_portal.guardian().call().await?._0;
    if portal_guardian_address != guardian_address {
        error!(
            "OptimismPortal Guardian is {portal_guardian_address} instead of {guardian_address}."
        );
        exit(3);
    }

    // initialize owner wallet
    info!("Initializing owner wallet.");
    let owner_signer = LocalSigner::from_str(&args.owner_key)?;
    let owner_wallet = EthereumWallet::from(owner_signer);
    let owner_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(&owner_wallet)
        .on_http(args.l1_node_address.as_str().try_into()?);
    // Init registry and factory contracts
    let anchor_state_registry = kailua_contracts::IAnchorStateRegistry::new(
        Address::from_str(&args.registry_contract)?,
        &owner_provider,
    );
    info!("AnchorStateRegistry({:?})", anchor_state_registry.address());
    let dispute_game_factory = kailua_contracts::IDisputeGameFactory::new(
        anchor_state_registry.disputeGameFactory().call().await?._0,
        &owner_provider,
    );
    info!("DisputeGameFactory({:?})", dispute_game_factory.address());
    let game_count = dispute_game_factory.gameCount().call().await?.gameCount_;
    info!("There have been {game_count} games created using DisputeGameFactory");
    let dispute_game_factory_ownable = kailua_contracts::OwnableUpgradeable::new(
        anchor_state_registry.disputeGameFactory().call().await?._0,
        &owner_provider,
    );
    let factory_owner_address = dispute_game_factory_ownable
        .owner()
        .call()
        .await
        .context("Failed to query factory owner.")?
        ._0;
    let factory_owner_safe = kailua_contracts::Safe::new(factory_owner_address, &owner_provider);
    info!("Safe({:?})", factory_owner_safe.address());
    let safe_owners = factory_owner_safe.getOwners().call().await?._0;
    info!("Safe::owners({:?})", &safe_owners);
    let owner_address = owner_wallet.default_signer().address();
    if safe_owners.first().unwrap() != &owner_address {
        error!("Incorrect owner key.");
        exit(2);
    } else if safe_owners.len() != 1 {
        error!("Expected exactly one owner of safe account.");
        exit(1);
    }
    // initialize deployment wallet
    let deployer_signer = LocalSigner::from_str(&args.deployer_key)?;
    let deployer_wallet = EthereumWallet::from(deployer_signer);
    let deployer_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(&deployer_wallet)
        .on_http(args.l1_node_address.as_str().try_into()?);

    info!("Fetching rollup configuration from L2 nodes.");
    // fetch rollup config
    let config = fetch_rollup_config(&args.op_node_address, &args.l2_node_address, None).await?;
    let rollup_config_hash = config_hash(&config).expect("Configuration hash derivation error");
    info!("RollupConfigHash({})", hex::encode(rollup_config_hash));
    debug!("{:?}", &config);

    // Deploy FaultProofSetup contract
    // {
    info!("Deploying FaultProofSetup contract to L1 rpc.");
    let fault_dispute_game_type = 254;
    let fault_proof_game_type = 1337;
    let fault_proof_setup_contract = kailua_contracts::FaultProofSetup::deploy(
        &deployer_provider,
        fault_proof_game_type,
        fault_dispute_game_type,
        Address::from_str(&args.registry_contract)?,
    )
    .await
    .context("FaultProofSetup contract deployment error")?;
    info!("{:?}", &fault_proof_setup_contract);
    // }
    // Update dispute factory implementation to FaultProofSetup
    info!("Setting FaultProofSetup initialization bond value in DisputeGameFactory.");
    let bond_value = U256::from(1);
    crate::exec_safe_txn(
        dispute_game_factory.setInitBond(fault_proof_game_type, bond_value),
        &factory_owner_safe,
        owner_address,
    )
    .await
    .context("setInitBond 1 wei")?;
    assert_eq!(
        dispute_game_factory
            .initBonds(fault_proof_game_type)
            .call()
            .await?
            .bond_,
        bond_value
    );
    info!("Setting FaultProofSetup implementation address in DisputeGameFactory.");
    crate::exec_safe_txn(
        dispute_game_factory
            .setImplementation(fault_proof_game_type, *fault_proof_setup_contract.address()),
        &factory_owner_safe,
        owner_address,
    )
    .await
    .context("setImplementation FaultProofSetup")?;
    assert_eq!(
        dispute_game_factory
            .gameImpls(fault_proof_game_type)
            .call()
            .await?
            .impl_,
        *fault_proof_setup_contract.address()
    );
    // Create new setup game
    let fault_dispute_anchor = anchor_state_registry
        .anchors(fault_dispute_game_type)
        .call()
        .await?;
    let root_claim = fault_dispute_anchor._0;
    let extra_data = Bytes::from(fault_dispute_anchor._1.abi_encode_packed());
    // Skip setup if target anchor already exists
    let fault_proof_setup_address = dispute_game_factory
        .games(fault_proof_game_type, root_claim, extra_data.clone())
        .call()
        .await
        .context("fault_proof_setup_address")?
        .proxy_;
    if fault_proof_setup_address.is_zero() {
        info!(
            "Creating new FaultProofSetup game instance from {} ({}).",
            fault_dispute_anchor._1, fault_dispute_anchor._0
        );
        dispute_game_factory
            .create(fault_proof_game_type, root_claim, extra_data.clone())
            .value(bond_value)
            .send()
            .await
            .context("create FaultProofSetup (send)")?
            .get_receipt()
            .await
            .context("create FaultProofSetup (get_receipt)")?;
    } else {
        info!(
            "Already found a game instance for anchor {} ({}).",
            fault_dispute_anchor._1, fault_dispute_anchor._0
        );
    }
    let fault_proof_setup_address = dispute_game_factory
        .games(fault_proof_game_type, root_claim, extra_data)
        .call()
        .await
        .context("fault_proof_setup_address")?
        .proxy_;
    let fault_proof_setup =
        kailua_contracts::FaultProofSetup::new(fault_proof_setup_address, &owner_provider);
    let status = fault_proof_setup.status().call().await?._0;
    if status == 0 {
        info!("Resolving FaultProofSetup instance");
        fault_proof_setup
            .resolve()
            .send()
            .await
            .context("FaultProofSetup::resolve (send)")?
            .get_receipt()
            .await
            .context("FaultProofSetup::resolve (get_receipt)")?;
    } else {
        info!("Game instance is not ongoing ({status})");
    }
    // Deploy MockVerifier contract
    // {
    info!("Deploying MockVerifier contract to L1 rpc.");
    let mock_verifier_contract = kailua_contracts::MockVerifier::deploy(&deployer_provider)
        .await
        .context("MockVerifier contract deployment error")?;
    info!("{:?}", &mock_verifier_contract);
    // }
    // Deploy FaultProofGame contract
    // {
    info!("Deploying FaultProofGame contract to L1 rpc.");
    let fault_proof_game_contract = kailua_contracts::FaultProofGame::deploy(
        &deployer_provider,
        *mock_verifier_contract.address(),
        bytemuck::cast::<[u32; 8], [u8; 32]>(KAILUA_FPVM_CHAINED_ID).into(),
        rollup_config_hash.into(),
        Uint::from(128),
        60,
        1337,
        Address::from_str(&args.registry_contract)?,
    )
    .await
    .context("FaultProofGame contract deployment error")?;
    info!("{:?}", &fault_proof_game_contract);
    // }
    // Update implementation to FaultProofGame
    info!("Setting FaultProofGame implementation address in DisputeGameFactory.");
    crate::exec_safe_txn(
        dispute_game_factory
            .setImplementation(fault_proof_game_type, *fault_proof_game_contract.address()),
        &factory_owner_safe,
        owner_address,
    )
    .await
    .context("setImplementation FaultProofGame")?;
    // Update the respectedGameType as the guardian
    info!("Setting respectedGameType in OptimismPortal.");
    optimism_portal
        .setRespectedGameType(fault_proof_game_type)
        .send()
        .await
        .context("setImplementation FaultProofGame")?
        .get_receipt()
        .await?;
    info!("FraudProofGame installed.");
    Ok(())
}
