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

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Uint};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::LocalSigner;
use anyhow::Context;
use clap::Parser;
use kailua_build::KAILUA_FPVM_CHAINED_ID;
use kailua_cli::{Cli, DeployArgs};
use kailua_common::config_hash;
use kailua_host::fetch_rollup_config;
use kona_host::init_tracing_subscriber;
use std::str::FromStr;
use tracing::{debug, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing_subscriber(cli.verbosity())?;

    match cli {
        Cli::Deploy(deploy_args) => deploy(deploy_args).await?,
    }
    Ok(())
}

pub async fn deploy(args: DeployArgs) -> anyhow::Result<()> {
    info!("Fetching rollup configuration from L2 nodes.");
    // fetch rollup config
    let config = fetch_rollup_config(&args.op_node_address, &args.l2_node_address, None).await?;
    let rollup_config_hash = config_hash(&config).expect("Configuration hash derivation error");
    info!("RollupConfigHash({})", hex::encode(rollup_config_hash));
    debug!("{:?}", &config);
    // initialize deployment wallet
    let eth_signer =
        LocalSigner::from_str(&args.deployer_key)?;
    let eth_wallet = EthereumWallet::from(eth_signer);
    let eth_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(&eth_wallet)
        .on_http(args.l1_node_address.as_str().try_into()?);
    // Init registry and factory contracts
    let anchor_state_registry = kailua_contracts::AnchorStateRegistry::new(
        Address::from_str(&args.registry_contract)?,
        &eth_provider,
    );
    info!("AnchorStateRegistry({:?})", anchor_state_registry.address());
    let dispute_game_factory = kailua_contracts::DisputeGameFactory::new(
        anchor_state_registry.disputeGameFactory().call().await?._0,
        &eth_provider,
    );
    info!("DisputeGameFactory({:?})", dispute_game_factory.address());
    let factory_owner = dispute_game_factory
        .owner()
        .call()
        .await
        .context("Failed to query factory owner.")?
        ._0;
    info!("DisputeGameFactory::owner({:?})", &factory_owner);
    // Deploy FaultProofSetup contract
    // {
        info!("Deploying FaultProofSetup contract to L1 rpc.");
        let fault_proof_setup_contract = kailua_contracts::FaultProofSetup::deploy(
            &eth_provider,
            1337,
            1,
            Address::from_str(&args.registry_contract)?,
        )
            .await
            .context("FaultProofSetup contract deployment error")?;
        info!("{:?}", &fault_proof_setup_contract);
    // }
    // Deploy MockVerifier contract
    // {
        info!("Deploying MockVerifier contract to L1 rpc.");
        let mock_verifier_contract = kailua_contracts::MockVerifier::deploy(&eth_provider)
            .await
            .context("MockVerifier contract deployment error")?;
        info!("{:?}", &mock_verifier_contract);
    // }
    // Deploy FaultProofGame contract
    // {
        info!("Deploying FaultProofGame contract to L1 rpc.");
        let fault_proof_game_contract = kailua_contracts::FaultProofGame::deploy(
            &eth_provider,
            *mock_verifier_contract.address(),
            bytemuck::cast::<[u32; 8], [u8; 32]>(KAILUA_FPVM_CHAINED_ID).into(),
            rollup_config_hash.into(),
            Uint::from(128),
            10 * 60 * 60,
            1337,
            Address::from_str(&args.registry_contract)?,
        )
        .await
        .context("FaultProofGame contract deployment error")?;
        info!("{:?}", &fault_proof_game_contract);
    // }
    // todo: Update dispute factory implementation

    Ok(())
}
