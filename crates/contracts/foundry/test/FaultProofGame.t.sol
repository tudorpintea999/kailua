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
//
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.15;

import "../lib/forge-std/src/Test.sol";
import "../lib/forge-std/src/console.sol";
import "./MockVerifier.sol";
import "../src/vendor/FlatOPImportV1.4.0.sol";
import "../src/FaultProofGame.sol";

contract FaultProofGameTest is Test {
    uint256 mainnetFork;
    MockVerifier verifier;
    FaultProofGame faultProofGame;
    GameType faultProofGameType = GameType.wrap(1337);
    GameType faultDisputeGameType = GameType.wrap(1); // Use the anchor of the permissioned fault dispute game
    IDisputeGameFactory factory = IDisputeGameFactory(0xe5965Ab5962eDc7477C8520243A95517CD252fA9);
    address factoryOwner = 0x5a0Aae59D09fccBdDb6C6CcEB07B7279367C3d2A;
    IDelayedWETH wrappedETH = IDelayedWETH(0xE497B094d6DbB3D5E4CaAc9a14696D7572588d14);
    IAnchorStateRegistry registry = IAnchorStateRegistry(0x18DAc71c228D1C32c99489B7323d441E1175e443);

    function setUp() external {
        mainnetFork = vm.createSelectFork(vm.envString("L1_NODE_ADDRESS"), 20634349);
        verifier = new MockVerifier();
        faultProofGame = new FaultProofGame(
            verifier,
            bytes32(0),
            faultProofGameType,
            256,
            Duration.wrap(10 hours),
            wrappedETH,
            registry,
            10,
            faultDisputeGameType
        );
        // Impersonate OP mainnet owner and install the fault proof game in the dispute game factory
        vm.startPrank(factoryOwner);
        factory.setInitBond(faultProofGameType, 1 wei);
        factory.setImplementation(faultProofGameType, IDisputeGame(faultProofGame));
        vm.stopPrank();
        // Impersonate some random rich address
        vm.startPrank(address(0x2d89034424Db22C9c555f14692a181B22B17E42C));
    }

    function testMockFaultProof() public {
        assertEq(vm.activeFork(), mainnetFork);
        // Send a new proposal one block ahead
        (, uint256 anchorBlockNum) = registry.anchors(faultDisputeGameType);
        bytes32 outputClaim = keccak256("I am unprovable.");
        uint256 outputBlockNum = anchorBlockNum + 2;
        FaultProofGame gameInstance = FaultProofGame(
            address(
                factory.create{value: 1 wei}(
                    faultProofGameType, Claim.wrap(outputClaim), abi.encodePacked(outputBlockNum)
                )
            )
        );
        // Check that we cannot resolve this game yet
        vm.expectRevert(ClockNotExpired.selector);
        gameInstance.resolve();
        // Prove fault
        gameInstance.prove("", true);
        // Resolve and assert that attacker won
        assert(gameInstance.resolve() == GameStatus.CHALLENGER_WINS);
    }

    function testMockValidityProof() public {
        assertEq(vm.activeFork(), mainnetFork);
        // Send a new proposal one block ahead
        (, uint256 anchorBlockNum) = registry.anchors(faultDisputeGameType);
        FaultProofGame gameInstance = FaultProofGame(
            address(
                factory.create{value: 1 wei}(
                    faultProofGameType, Claim.wrap(keccak256("I am provable.")), abi.encodePacked(anchorBlockNum + 128)
                )
            )
        );
        // Check that we cannot resolve this game yet
        vm.expectRevert(ClockNotExpired.selector);
        gameInstance.resolve();
        // Prove validity
        gameInstance.prove("", false);
        // Resolve and assert that defender won
        assert(gameInstance.resolve() == GameStatus.DEFENDER_WINS);
    }

    function testTimeout() public {
        assertEq(vm.activeFork(), mainnetFork);
        // Send a new proposal one block ahead
        (, uint256 anchorBlockNum) = registry.anchors(faultDisputeGameType);
        FaultProofGame gameInstance = FaultProofGame(
            address(
                factory.create{value: 1 wei}(
                    faultProofGameType, Claim.wrap(keccak256("I am provable.")), abi.encodePacked(anchorBlockNum + 128)
                )
            )
        );
        // Check that we cannot resolve this game yet
        vm.expectRevert(ClockNotExpired.selector);
        gameInstance.resolve();
        // Advance chain by an hour
        vm.warp(vm.getBlockTimestamp() + 10 hours);
        // Resolve and assert that defender won
        assert(gameInstance.resolve() == GameStatus.DEFENDER_WINS);
    }
}
