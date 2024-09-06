# Kailua

Kailua uses the RISC-Zero zkVM to verifiably run Optimism's [Kona][kona] and secure rollups with cryptographic proofs for faster finality.

## Development Status

`kailua` as well as `kona` are still in active development and are NOT suitable for production usage.

## Fraud/Validity Proofs

Kailua enables rollup operators to add a new `FaultProofGame` contract, compatible with Bedrock contracts `v1.4.0` and above, using the `DisputeGameFactory` rollup instance to their deployment that relies on RISC-Zero zkVM proofs to finalize/dismiss output proposals.

`FaultProofGame` can be configured to either pessimistically require a proof before any game can be resolved, or optimistically allow outputs to be accepted after a timeout if no fraud proof is published against it.

## Prerequisites
1. [rust](https://www.rust-lang.org/tools/install)
2. [just](https://just.systems/man/en/chapter_1.html)
3. [kurtosis](https://docs.kurtosis.com/install)
4. [foundry](https://book.getfoundry.sh/getting-started/installation)

## Usage

1. `just build`
   * Builds the cargo and foundry projects
2. `just devnet-up`
   * Starts a local OP Stack devnet using kurtosis.
   * After you're done, you can stop the devnet with `just devnet-down`
   * Note down the below local endpoints from the final kurtosis output
   ```text
   =================== User Services ===================
   Name                      Ports                              
   el-1-geth-lighthouse      rpc: 8545/tcp  -> <L1_NODE>
   cl-1-lighthouse-geth      http: 4000/tcp -> <L1_RPC>
   op-el-1-op-geth-op-node   rpc: 8545/tcp  -> <L2_NODE>
   op-cl-1-op-node-op-geth   http: 8547/tcp -> <L2_RPC> 
   ```
3. `just devnet-deploy <L1_NODE> <L1_RPC> <L2_NODE> <L2_RPC>`
   * Use the local endpoints from your terminal's kurtosis output.
   * Deploys a base `FaultProofGame` contract configured with your `RollupConfig` and guest image ids.
4. Integrate `FaultProofGame` into your rollup's `DisputeGameFactory` using the following methods:
   1. Call `setInitBond` to set the required bond for proposing outputs using the `FaultProofGame`. 
   2. Call `setImplementation` to set the address of the `FaultProofGame` contract you've deployed.
[//]: # (5. Update the `AnchorStateRegistry` to copy the last confirmed output from another game.)
5. Invoke Kailua to generate proofs.

## TODO:
1. Embed immutable hash of `RollupConfig` in `FaultProofGame` and `fpvm`.
2. 

## Questions, Feedback, and Collaborations

We'd love to hear from you on [Discord][discord] or [Twitter][twitter].

[bonsai access]: https://bonsai.xyz/apply
[cargo-risczero]: https://docs.rs/cargo-risczero
[crates]: https://github.com/risc0/risc0/blob/main/README.md#rust-binaries
[dev-docs]: https://dev.risczero.com
[dev-mode]: https://dev.risczero.com/api/generating-proofs/dev-mode
[discord]: https://discord.gg/risczero
[docs.rs]: https://docs.rs/releases/search?query=risc0
[examples]: https://github.com/risc0/risc0/tree/main/examples
[risc0-build]: https://docs.rs/risc0-build
[risc0-repo]: https://www.github.com/risc0/risc0
[risc0-zkvm]: https://docs.rs/risc0-zkvm
[rustup]: https://rustup.rs
[rust-toolchain]: rust-toolchain.toml
[twitter]: https://twitter.com/risczero
[zkvm-overview]: https://dev.risczero.com/zkvm
[zkhack-iii]: https://www.youtube.com/watch?v=Yg_BGqj_6lg&list=PLcPzhUaCxlCgig7ofeARMPwQ8vbuD6hC5&index=5
[kona]: https://github.com/ethereum-optimism/kona