// use crate::oracle::CachingOracle;
use crate::oracle::{HINT_WRITER, ORACLE_READER};
use kailua_common::oracle::ORACLE_LRU_SIZE;
use kona_client::l1::{DerivationDriver, OracleBlobProvider, OracleL1ChainProvider};
use kona_client::l2::OracleL2ChainProvider;
use kona_client::{BootInfo, CachingOracle};
use kona_executor::StatelessL2BlockExecutor;
use kona_primitives::L2AttributesWithParent;
use std::sync::Arc;
use tracing::info;

pub async fn run_native_client() -> anyhow::Result<()> {
    kona_common::block_on(async move {
        ////////////////////////////////////////////////////////////////
        //                          PROLOGUE                          //
        ////////////////////////////////////////////////////////////////

        info!("PROLOGUE");
        let oracle = Arc::new(CachingOracle::new(
            ORACLE_LRU_SIZE,
            ORACLE_READER,
            HINT_WRITER,
        ));
        let boot = Arc::new(
            BootInfo::load(oracle.as_ref())
                .await
                .expect("Failed to load boot info"),
        );
        let l1_provider = OracleL1ChainProvider::new(boot.clone(), oracle.clone());
        let l2_provider = OracleL2ChainProvider::new(boot.clone(), oracle.clone());
        let beacon = OracleBlobProvider::new(oracle.clone());

        ////////////////////////////////////////////////////////////////
        //                   DERIVATION & EXECUTION                   //
        ////////////////////////////////////////////////////////////////
        info!("DERIVATION & EXECUTION");
        let mut driver = DerivationDriver::new(
            boot.as_ref(),
            oracle.as_ref(),
            beacon,
            l1_provider,
            l2_provider.clone(),
        )
        .await
        .expect("Faled to init driver");
        let L2AttributesWithParent { attributes, .. } = driver
            .produce_disputed_payload()
            .await?
            .expect("Failed to derive payload attributes");

        let mut executor: StatelessL2BlockExecutor<_, _> =
            StatelessL2BlockExecutor::builder(&boot.rollup_config)
                .with_parent_header(driver.take_l2_safe_head_header())
                .with_fetcher(l2_provider.clone())
                .with_hinter(l2_provider)
                .build()?;
        executor.execute_payload(attributes)?;
        executor.compute_output_root()?;

        Ok::<_, anyhow::Error>(())
    })
}
