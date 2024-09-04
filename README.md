# Kailua

Kailua uses the RISC-Zero zkVM to verifiably run Optimism's [Kona][kona] and secure rollups with cryptographic proofs for faster finality.

## Development Status

`kailua` as well as `kona` are still in active development and are not suitable for production usage.

## Fraud/Validity Proofs

Kailua enables rollup operators to add a new `FaultProofGame` contract, compatible with Bedrock contracts `v1.4.0` and above, using the `DisputeGameFactory` rollup instance to their deployment that relies on RISC-Zero zkVM proofs to finalize/dismiss output proposals.

`FaultProofGame` can be configured to either pessimistically require a proof before any game can be resolved, or optimistically allow outputs to be accepted after a timeout if no fraud proof is published against it.

## Usage

1. Hardcode your `RollupConfig` into the `fpvm` binary and perform a reproducible docker build.
2. Deploy a `FaultProofGame` contract with your `fpvm` and `fpvm-chained` image ids.
3. Integrate `FaultProofGame` into your rollup's `DisputeGameFactory` using the following methods:
   1. Call `setInitBond` to set the required bond for proposing outputs using the `FaultProofGame`. 
   2. Call `setImplementation` to set the address of the `FaultProofGame` contract you've deployed.
4. Update the `AnchorStateRegistry` to copy the last confirmed output from another game.
5. Invoke Kailua to generate proofs.

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