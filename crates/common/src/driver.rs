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

// Parts of the below code are copied from various files under https://github.com/anton-rs/kona.
// As such, the copied parts may not be subject to the license or copyright notice above.

use alloy_primitives::Sealed;
use anyhow::anyhow;
use kona_client::l1::{OracleL1ChainProvider, OraclePipeline};
use kona_client::l2::OracleL2ChainProvider;
use kona_client::{BootInfo, HintType};
use kona_derive::{
    errors::StageError,
    pipeline::{Pipeline, PipelineBuilder, StepResult},
    sources::EthereumDataSource,
    stages::StatefulAttributesBuilder,
    traits::{BlobProvider, ChainProvider, L2ChainProvider},
};
use kona_mpt::TrieDBFetcher;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_primitives::{BlockInfo, Header, L2AttributesWithParent, L2BlockInfo};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{info, warn};

/// The [DerivationDriver] struct is responsible for handling the [L2PayloadAttributes] derivation
/// process.
///
/// It contains an inner [OraclePipeline] that is used to derive the attributes, backed by
/// oracle-based data sources.
///
/// [L2PayloadAttributes]: kona_primitives::L2PayloadAttributes

#[derive(Debug)]
pub struct DerivationDriver<O, B>
where
    O: CommsClient + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
{
    /// The current L2 safe head.
    pub l2_safe_head: L2BlockInfo,
    /// The header of the L2 safe head.
    pub l2_safe_head_header: Sealed<Header>,
    /// The inner pipeline.
    pub pipeline: OraclePipeline<O, B>,
}

impl<O, B> DerivationDriver<O, B>
where
    O: CommsClient + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
{
    /// Creates a new [DerivationDriver] with the given configuration, blob provider, and chain
    /// providers.
    ///
    /// ## Takes
    /// - `cfg`: The rollup configuration.
    /// - `blob_provider`: The blob provider.
    /// - `chain_provider`: The L1 chain provider.
    /// - `l2_chain_provider`: The L2 chain provider.
    ///
    /// ## Returns
    /// - A new [DerivationDriver] instance.
    pub async fn new(
        boot_info: &BootInfo,
        caching_oracle: &O,
        blob_provider: B,
        mut chain_provider: OracleL1ChainProvider<O>,
        mut l2_chain_provider: OracleL2ChainProvider<O>,
    ) -> anyhow::Result<Self> {
        let cfg = Arc::new(boot_info.rollup_config.clone());

        // Fetch the startup information.
        let (l1_origin, l2_safe_head, l2_safe_head_header) = Self::find_startup_info(
            caching_oracle,
            boot_info,
            &mut chain_provider,
            &mut l2_chain_provider,
        )
        .await?;

        // Construct the pipeline.
        let attributes = StatefulAttributesBuilder::new(
            cfg.clone(),
            l2_chain_provider.clone(),
            chain_provider.clone(),
        );
        let dap = EthereumDataSource::new(chain_provider.clone(), blob_provider, &cfg);

        // Walk back the starting L1 block by `channel_timeout` to ensure that the full channel is
        // captured.
        let channel_timeout = boot_info
            .rollup_config
            .channel_timeout(l2_safe_head.block_info.timestamp);
        let mut l1_origin_number = l1_origin.number.saturating_sub(channel_timeout);
        if l1_origin_number < boot_info.rollup_config.genesis.l1.number {
            l1_origin_number = boot_info.rollup_config.genesis.l1.number;
        }
        let l1_origin = chain_provider
            .block_info_by_number(l1_origin_number)
            .await?;

        let pipeline = PipelineBuilder::new()
            .rollup_config(cfg)
            .dap_source(dap)
            .l2_chain_provider(l2_chain_provider)
            .chain_provider(chain_provider)
            .builder(attributes)
            .origin(l1_origin)
            .build();

        Ok(Self {
            l2_safe_head,
            l2_safe_head_header,
            pipeline,
        })
    }

    /// Produces the disputed [L2AttributesWithParent] payload, directly after the starting L2
    /// output root passed through the [BootInfo].
    pub async fn produce_disputed_payload(
        &mut self,
    ) -> anyhow::Result<Option<L2AttributesWithParent>> {
        // As we start the safe head at the disputed block's parent, we step the pipeline until the
        // first attributes are produced. All batches at and before the safe head will be
        // dropped, so the first payload will always be the disputed one.
        let mut attributes = None;
        while attributes.is_none() {
            match self.pipeline.step(self.l2_safe_head).await {
                StepResult::PreparedAttributes => {
                    info!(target: "client_derivation_driver", "Stepped derivation pipeline")
                }
                StepResult::AdvancedOrigin => {
                    info!(target: "client_derivation_driver", "Advanced origin")
                }
                StepResult::OriginAdvanceErr(e) | StepResult::StepFailed(e) => {
                    warn!(target: "client_derivation_driver", "Failed to step derivation pipeline: {:?}", e);

                    // Break the loop unless the error signifies that there is not enough data to
                    // complete the current step. In this case, we retry the step to see if other
                    // stages can make progress.
                    if !matches!(e, StageError::NotEnoughData) {
                        break;
                    }
                }
            }

            attributes = self.pipeline.next();
        }

        Ok(attributes)
    }

    /// Finds the startup information for the derivation pipeline.
    ///
    /// ## Takes
    /// - `caching_oracle`: The caching oracle.
    /// - `boot_info`: The boot information.
    /// - `chain_provider`: The L1 chain provider.
    /// - `l2_chain_provider`: The L2 chain provider.
    ///
    /// ## Returns
    /// - A tuple containing the L1 origin block information and the L2 safe head information.
    pub async fn find_startup_info(
        caching_oracle: &O,
        boot_info: &BootInfo,
        chain_provider: &mut OracleL1ChainProvider<O>,
        l2_chain_provider: &mut OracleL2ChainProvider<O>,
    ) -> anyhow::Result<(BlockInfo, L2BlockInfo, Sealed<Header>)> {
        // Find the initial safe head, based off of the starting L2 block number in the boot info.
        caching_oracle
            .write(&HintType::StartingL2Output.encode_with(&[boot_info.l2_output_root.as_ref()]))
            .await?;
        let mut output_preimage = [0u8; 128];
        caching_oracle
            .get_exact(
                PreimageKey::new(*boot_info.l2_output_root, PreimageKeyType::Keccak256),
                &mut output_preimage,
            )
            .await?;

        let safe_hash = output_preimage[96..128]
            .try_into()
            .map_err(|_| anyhow!("Invalid L2 output root"))?;
        let safe_header = l2_chain_provider.header_by_hash(safe_hash)?;
        let safe_head_info = l2_chain_provider
            .l2_block_info_by_number(safe_header.number)
            .await?;

        let l1_origin = chain_provider
            .block_info_by_number(safe_head_info.l1_origin.number)
            .await?;

        Ok((
            l1_origin,
            safe_head_info,
            Sealed::new_unchecked(safe_header, safe_hash),
        ))
    }
}
