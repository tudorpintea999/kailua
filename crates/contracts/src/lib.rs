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

use alloy::sol;

sol!(
    #[sol(rpc)]
    FaultProofGame,
    "foundry/out/FaultProofGame.sol/FaultProofGame.json"
);

sol!(
    #[sol(rpc)]
    FaultProofSetup,
    "foundry/out/FaultProofSetup.sol/FaultProofSetup.json"
);

sol!(
    #[sol(rpc)]
    MockVerifier,
    "foundry/out/MockVerifier.sol/MockVerifier.json"
);

sol! {
    type GameId is bytes32;
}

sol! {
    type Claim is bytes32;
}

sol! {
    type Timestamp is uint64;
}

sol!(
    #[sol(rpc)]
    DisputeGameFactory,
    "foundry/out/FlatOPImportV1.4.0.sol/DisputeGameFactory.json"
);

sol!(
    #[sol(rpc)]
    AnchorStateRegistry,
    "foundry/out/FlatOPImportV1.4.0.sol/AnchorStateRegistry.json"
);
