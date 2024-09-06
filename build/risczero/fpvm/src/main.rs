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

use kailua_common::blobs::RISCZeroBlobProvider;
use kona_client::l1::{DerivationDriver, OracleBlobProvider, OracleL1ChainProvider};
use kona_client::l2::OracleL2ChainProvider;
use kona_client::BootInfo;
use kona_executor::StatelessL2BlockExecutor;
use kona_primitives::{Header, L2AttributesWithParent};
use std::sync::Arc;
use kailua_common::oracle::{CachingRISCZeroOracle, ORACLE_LRU_SIZE};
use kailua_common::BasicBootInfo;
use risc0_zkvm::guest::env;

fn main() -> anyhow::Result<()> {
    kona_common::block_on(async move {
        ////////////////////////////////////////////////////////////////
        //                          PROLOGUE                          //
        ////////////////////////////////////////////////////////////////
        env::log("PROLOGUE");

        let oracle = Arc::new(CachingRISCZeroOracle::new(ORACLE_LRU_SIZE));
        let boot = Arc::new(BootInfo::load(oracle.as_ref()).await?);

        let l1_provider = OracleL1ChainProvider::new(boot.clone(), oracle.clone());
        let l2_provider = OracleL2ChainProvider::new(boot.clone(), oracle.clone());
        let blob_provider = OracleBlobProvider::new(oracle.clone());
        let beacon = RISCZeroBlobProvider::new(blob_provider);

        ////////////////////////////////////////////////////////////////
        //                   DERIVATION & EXECUTION                   //
        ////////////////////////////////////////////////////////////////
        env::log("DERIVATION");
        let mut driver = DerivationDriver::new(
            boot.as_ref(),
            oracle.as_ref(),
            beacon,
            l1_provider,
            l2_provider.clone(),
        )
        .await?;

        env::log("PAYLOAD");
        let L2AttributesWithParent { attributes, .. } = driver.produce_disputed_payload().await?;

        env::log("EXECUTION");
        let mut executor: StatelessL2BlockExecutor<_, _> =
            StatelessL2BlockExecutor::builder(&boot.rollup_config)
                .with_parent_header(driver.take_l2_safe_head_header())
                .with_fetcher(l2_provider.clone())
                .with_hinter(l2_provider)
                .build()?;

        env::log("HEADER");
        let Header {
            number: l2_claim_block,
            ..
        } = *executor.execute_payload(attributes)?;

        env::log("OUTPUT");
        let l2_claim = executor.compute_output_root()?;

        ////////////////////////////////////////////////////////////////
        //                          EPILOGUE                          //
        ////////////////////////////////////////////////////////////////
        env::commit(&BasicBootInfo {
            l1_head: boot.l1_head,
            l2_output_root: boot.l2_output_root,
            l2_claim,
            l2_claim_block,
            chain_id: boot.chain_id,
        });

        Ok::<_, anyhow::Error>(())
    })
}
