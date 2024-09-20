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

import "./vendor/FlatOPImportV1.4.0.sol";
import "./vendor/FlatR0ImportV1.0.0.sol";

/// @notice Occurs when the anchored game is not finalized
error InvalidAnchoredGame();

/// @notice Occurs when the anchored game block number is different
error BlockNumberMismatch(uint256 anchored, uint256 initialized);

contract FaultProofSetup is Clone, IDisputeGame {
    /// @notice Semantic version.
    /// @custom:semver 0.1.0
    string public constant version = "0.1.0";

    // ------------------------------
    // Immutable configuration
    // ------------------------------

    /// @notice The game type ID
    GameType internal immutable GAME_TYPE;

    /// @notice The anchored game type ID to clone
    GameType internal immutable ANCHORED_GAME_TYPE;

    /// @notice The anchor state registry.
    IAnchorStateRegistry internal immutable ANCHOR_STATE_REGISTRY;

    /// @notice Returns the game type.
    function gameType() external view returns (GameType gameType_) {
        gameType_ = GAME_TYPE;
    }

    /// @notice Returns the anchored game type.
    function anchoredGameType() external view returns (GameType anchoredGameType_) {
        anchoredGameType_ = ANCHORED_GAME_TYPE;
    }

    /// @notice Returns the anchor state registry contract.
    function anchorStateRegistry() external view returns (IAnchorStateRegistry registry_) {
        registry_ = ANCHOR_STATE_REGISTRY;
    }

    constructor(GameType _gameType, GameType _anchoredGameType, IAnchorStateRegistry _anchorStateRegistry) {
        GAME_TYPE = _gameType;
        ANCHORED_GAME_TYPE = _anchoredGameType;
        ANCHOR_STATE_REGISTRY = _anchorStateRegistry;
    }

    /// @notice The starting timestamp of the game
    Timestamp public createdAt;

    /// @notice The timestamp of the game's global resolution.
    Timestamp public resolvedAt;

    /// @inheritdoc IDisputeGame
    GameStatus public status;

    /// @notice Initializes the contract
    /// @dev This function may only be called once.
    function initialize() external payable {
        // INVARIANT: The game must not have already been initialized.
        if (createdAt.raw() > 0) revert AlreadyInitialized();

        if ((rootClaim().raw() != bytes32(0)) || (l2BlockNumber() != 0)) {
            // Validate the cloned anchor state
            IDisputeGameFactory disputeGameFactory = ANCHOR_STATE_REGISTRY.disputeGameFactory();

            (IDisputeGame proxyAddress,) = disputeGameFactory.games(ANCHORED_GAME_TYPE, rootClaim(), this.extraData());

            IFaultDisputeGame anchoredGame = IFaultDisputeGame(address(proxyAddress));

            // Validate that the game is resolved correctly
            if (anchoredGame.status() != GameStatus.DEFENDER_WINS) revert InvalidAnchoredGame();

            // Revert if different proposal root
            if (anchoredGame.rootClaim().raw() != rootClaim().raw()) revert UnexpectedRootClaim(rootClaim());

            // Revert if different proposal root block number
            if (anchoredGame.l2BlockNumber() != l2BlockNumber()) {
                revert BlockNumberMismatch(anchoredGame.l2BlockNumber(), l2BlockNumber());
            }
        }

        // Set the game's starting timestamp
        createdAt = Timestamp.wrap(uint64(block.timestamp));
    }

    /// @notice If all necessary information has been gathered, this function should mark the game
    ///         status as either `CHALLENGER_WINS` or `DEFENDER_WINS` and return the status of
    ///         the resolved game.
    /// @dev May only be called if the `status` is `IN_PROGRESS`.
    /// @return status_ The status of the game after resolution.
    function resolve() external returns (GameStatus status_) {
        // INVARIANT: Resolution cannot occur unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // INVARIANT: Only the factory owner can resolve the setup game
        //        IDisputeGameFactory disputeGameFactory = ANCHOR_STATE_REGISTRY.disputeGameFactory();
        //        if (msg.sender != disputeGameFactory.owner())

        // Update the status and emit the resolved event, note that we're performing a storage update here.
        emit Resolved(status = status_ = GameStatus.DEFENDER_WINS);

        // Mark resolution timestamp
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));

        // Try to update the anchor state, this should not revert.
        ANCHOR_STATE_REGISTRY.tryUpdateAnchorState();
    }

    // ------------------------------
    // Initialization data helpers
    // ------------------------------

    /// @inheritdoc IDisputeGame
    function gameCreator() public pure returns (address creator_) {
        creator_ = _getArgAddress(0x00);
    }

    /// @inheritdoc IDisputeGame
    function rootClaim() public pure returns (Claim rootClaim_) {
        rootClaim_ = Claim.wrap(_getArgBytes32(0x14));
    }

    /// @inheritdoc IDisputeGame
    function l1Head() public pure returns (Hash l1Head_) {
        l1Head_ = Hash.wrap(_getArgBytes32(0x34));
    }

    /// @notice The l2BlockNumber of the claim's output root.
    function l2BlockNumber() public pure returns (uint256 l2BlockNumber_) {
        l2BlockNumber_ = _getArgUint256(0x54);
    }

    /// @notice Getter for the extra data.
    /// @dev `clones-with-immutable-args` argument #2
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function extraData() external pure returns (bytes memory extraData_) {
        // The extra data starts at the second word within the cwia calldata and
        // is 32 bytes long.
        extraData_ = _getArgBytes(0x54, 0x20);
    }

    /// @notice A compliant implementation of this interface should return the components of the
    ///         game UUID's preimage provided in the cwia payload. The preimage of the UUID is
    ///         constructed as `keccak256(gameType . rootClaim . extraData)` where `.` denotes
    ///         concatenation.
    /// @return gameType_ The type of proof system being used.
    /// @return rootClaim_ The root claim of the DisputeGame.
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function gameData() external view returns (GameType gameType_, Claim rootClaim_, bytes memory extraData_) {
        gameType_ = this.gameType();
        rootClaim_ = this.rootClaim();
        extraData_ = this.extraData();
    }
}
