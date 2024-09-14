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

/// @notice Denotes the proven status of the game
/// @custom:value NONE indicates that no proof has been submitted yet.
/// @custom:value FAULT indicates that a valid fault proof has been submitted.
/// @custom:value INTEGRITY indicates that a valid integrity proof has been submitted.
enum ProofStatus {
    NONE,
    FAULT,
    INTEGRITY
}

/// @notice Thrown when a proof is submitted for an already proven game
error AlreadyProven();

/// @notice Thrown when a proving fault for an unchallenged game
error UnchallengedGame();

/// @notice Thrown when a challenge is submitted against an already challenged game
error AlreadyChallenged();

/// @notice Thrown when a game is created with a parent instance from another game type
error GameTypeMismatch(GameType parentType, GameType expectedType);

/// @notice Thrown when a game is initialized for more blocks than the maximum allowed
error BlockCountExceeded(uint256 l2BlockNumber, uint256 rootBlockNumber);

/// @notice Emitted when the game is proven.
/// @param status The proven status of the game
event Proven(ProofStatus indexed status);

contract FaultProofGame is Clone, IDisputeGame {
    /// @notice Semantic version.
    /// @custom:semver 0.1.0
    string public constant version = "0.1.0";

    // ------------------------------
    // Immutable configuration
    // ------------------------------

    /// @notice The RISC Zero verifier contract
    IRiscZeroVerifier internal immutable RISC_ZERO_VERIFIER;

    /// @notice The RISC Zero image id of the fault proof program
    bytes32 internal immutable FPVM_IMAGE_ID;

    /// @notice The hash of the game configuration
    bytes32 internal immutable GAME_CONFIG_HASH;

    /// @notice The maximum number of blocks a claim may cover
    uint256 internal immutable MAX_BLOCK_COUNT;

    /// @notice The duration after which the proposal is accepted
    Duration internal immutable MAX_CLOCK_DURATION;

    /// @notice The game type ID
    GameType internal immutable GAME_TYPE;

    /// @notice The anchor state registry.
    IAnchorStateRegistry internal immutable ANCHOR_STATE_REGISTRY;

    /// @notice Returns the address of the RISC Zero verifier used by this contract
    function verifier() external view returns (IRiscZeroVerifier verifier_) {
        verifier_ = RISC_ZERO_VERIFIER;
    }

    /// @notice Returns the RISC Zero Image ID of the FPVM program used by this contract
    function imageId() external view returns (bytes32 imageId_) {
        imageId_ = FPVM_IMAGE_ID;
    }

    /// @notice Returns the hash of the configuration of this game
    function configHash() external view returns (bytes32 configHash_) {
        configHash_ = GAME_CONFIG_HASH;
    }

    /// @notice Returns the maximum number of blocks that can be covered by this game
    function maxBlockCount() external view returns (uint256 maxBlockCount_) {
        maxBlockCount_ = MAX_BLOCK_COUNT;
    }

    /// @notice Returns the max clock duration.
    function maxClockDuration() external view returns (Duration maxClockDuration_) {
        maxClockDuration_ = MAX_CLOCK_DURATION;
    }

    /// @notice Returns the game type.
    function gameType() external view returns (GameType gameType_) {
        gameType_ = GAME_TYPE;
    }

    /// @notice Returns the anchor state registry contract.
    function anchorStateRegistry() external view returns (IAnchorStateRegistry registry_) {
        registry_ = ANCHOR_STATE_REGISTRY;
    }

    constructor(
        IRiscZeroVerifier _verifierContract,
        bytes32 _imageId,
        bytes32 _configHash,
        uint256 _maxBlockCount,
        Duration _maxClockDuration,
        GameType _gameType,
        IAnchorStateRegistry _anchorStateRegistry
    ) {
        RISC_ZERO_VERIFIER = _verifierContract;
        FPVM_IMAGE_ID = _imageId;
        GAME_CONFIG_HASH = _configHash;
        GAME_TYPE = _gameType;
        MAX_BLOCK_COUNT = _maxBlockCount;
        MAX_CLOCK_DURATION = _maxClockDuration;
        ANCHOR_STATE_REGISTRY = _anchorStateRegistry;
    }

    /// @notice The starting timestamp of the game
    Timestamp public createdAt;

    /// @notice The timestamp of when a claim against the proposal was made
    Timestamp public challengedAt;

    /// @notice The proving timestamp of the game
    Timestamp public provenAt;

    /// @notice The timestamp of the game's global resolution.
    Timestamp public resolvedAt;

    /// @inheritdoc IDisputeGame
    GameStatus public status;

    /// @notice The current proof status of the game.
    ProofStatus public proofStatus;

    /// @notice The bond paid to initiate the game
    uint256 public bond;

    /// @notice The game challenger address
    address public challenger;

    /// @notice The game prover address
    address public prover;

    /// @notice Initializes the contract
    /// @dev This function may only be called once.
    function initialize() external payable {
        // INVARIANT: The game must not have already been initialized.
        if (createdAt.raw() > 0) revert AlreadyInitialized();

        // Revert if the calldata size is not the expected length.
        //
        // This is to prevent adding extra or omitting bytes from to `extraData` that result in a different game UUID
        // in the factory, but are not used by the game, which would allow for multiple dispute games for the same
        // output proposal to be created.
        //
        // Expected length: 0x7A
        // - 0x04 selector
        // - 0x14 creator address
        // - 0x20 root claim
        // - 0x20 l1 head
        // - 0x10 extraData (u64 l2BlockNumber, u64 parentGameIndex)
        // - 0x02 CWIA bytes
        assembly {
            if iszero(eq(calldatasize(), 0x6A)) {
                // Store the selector for `BadExtraData()` & revert
                mstore(0x00, 0x9824bdab)
                revert(0x1C, 0x04)
            }
        }

        // Do not allow the game to be initialized if the root claim corresponds to a block at or before the
        // starting block number.
        uint256 parentBlockNumber = parentGame().l2BlockNumber();
        if (l2BlockNumber() <= parentBlockNumber) revert UnexpectedRootClaim(rootClaim());

        // Do not initialize a game that covers more blocks than permitted
        if (l2BlockNumber() - parentBlockNumber > MAX_BLOCK_COUNT) {
            revert BlockCountExceeded(l2BlockNumber(), parentBlockNumber);
        }

        // Record the bonded value
        bond = msg.value;

        // Set the game's starting timestamp
        createdAt = Timestamp.wrap(uint64(block.timestamp));
    }

    /// @notice Challenges the proposed output to prevent it from being resolved until proven
    function challenge() external payable {
        // INVARIANT: Proofs cannot be submitted unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // INVARIANT: Proofs can only be submitted once
        if (proofStatus != ProofStatus.NONE) revert AlreadyProven();

        // INVARIANT: Only the first challenger is accepted
        if (challenger != address(0x0)) revert AlreadyChallenged();

        // INVARIANT: The `msg.value` must exactly equal the required bond.
        if (getRequiredBond() != msg.value) revert IncorrectBondAmount();

        // Set the game challenger address
        challenger = payable(msg.sender);

        // Set the game's challenge timestamp
        challengedAt = Timestamp.wrap(uint64(block.timestamp));
    }

    /// @notice Proves the integrity of faultiness of the output argued on by this contract
    function prove(bytes calldata proof, bool isFaultProof) public {
        // INVARIANT: Proofs cannot be submitted unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // INVARIANT: Proofs can only be submitted once
        if (proofStatus != ProofStatus.NONE) revert AlreadyProven();

        // INVARIANT: Can only prove fault after naming a challenger
        if (isFaultProof && challenger == address(0x0)) revert UnchallengedGame();

        // Construct the expected journal
        bytes32 journalDigest = sha256(
            abi.encodePacked(
                // The L1 head hash containing the safe L2 chain data that may reproduce the L2 head hash.
                l1Head().raw(),
                // The latest finalized L2 output root.
                parentGame().rootClaim().raw(),
                // The L2 output root claim.
                rootClaim().raw(),
                // The L2 claim block number.
                uint64(l2BlockNumber()),
                // The configuration hash for this game
                GAME_CONFIG_HASH,
                // True iff the proof demonstrates fraud, false iff it demonstrates integrity
                isFaultProof
            )
        );

        // reverts on failure
        RISC_ZERO_VERIFIER.verify(proof, FPVM_IMAGE_ID, journalDigest);

        // Update proof status
        emit Proven(proofStatus = isFaultProof ? ProofStatus.FAULT : ProofStatus.INTEGRITY);

        // Set the game's prover address
        prover = msg.sender;

        // Set the game's proving timestamp
        provenAt = Timestamp.wrap(uint64(block.timestamp));
    }

    /// @notice If all necessary information has been gathered, this function should mark the game
    ///         status as either `CHALLENGER_WINS` or `DEFENDER_WINS` and return the status of
    ///         the resolved game.
    /// @dev May only be called if the `status` is `IN_PROGRESS`.
    /// @return status_ The status of the game after resolution.
    function resolve() external returns (GameStatus status_) {
        // INVARIANT: Resolution cannot occur unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // INVARIANT: Resolution cannot occur unless the parent game is resolved.
        GameStatus parentGameStatus = parentGame().status();
        if (parentGameStatus == GameStatus.IN_PROGRESS) revert OutOfOrderResolution();

        if (parentGameStatus == GameStatus.CHALLENGER_WINS) {
            // Resolve based on invalid parent game (todo: optimize this challenging requirement)
            if (challenger == address(0x0)) revert UnchallengedGame();

            // Set the status in favor of the challenger
            status_ = GameStatus.CHALLENGER_WINS;
        } else if (proofStatus != ProofStatus.NONE) {
            // Resolve based on proofStatus
            if (proofStatus == ProofStatus.FAULT) {
                // Set the status in favor of the challenger
                status_ = GameStatus.CHALLENGER_WINS;
            } else if (proofStatus == ProofStatus.INTEGRITY) {
                // Set the status in favor of the proposer
                status_ = GameStatus.DEFENDER_WINS;
            }
        } else {
            // INVARIANT: Cannot resolve an unproven game unless the clock of its would-be proof has expired
            if (getChallengerDuration().raw() < MAX_CLOCK_DURATION.raw()) revert ClockNotExpired();

            // Optimistically resolve in favor of the proposer
            status_ = GameStatus.DEFENDER_WINS;
        }

        if (status_ == GameStatus.DEFENDER_WINS) {
            // If the proposal passes, we repay the proposer
            pay(bond, gameCreator());

            // If a validity proof was submitted, we pay the remainder to the prover
            if (prover != address(0x0)) {
                pay(address(this).balance, prover);
            }
        } else if (status_ == GameStatus.CHALLENGER_WINS) {
            // If the proposal fails, the challenger claims the entire pot
            pay(address(this).balance, challenger);
        }

        // Update game status in storage
        status = status_;

        // Mark resolution timestamp
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));

        // Update the status and emit the resolved event, note that we're performing a storage update here.
        emit Resolved(status = status_);

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
        l2BlockNumber_ = _getArgUint64(0x54);
    }

    /// @notice The index of the parent game in the `DisputeGameFactory`.
    function parentGameIndex() public pure returns (uint64 parentGameIndex_) {
        parentGameIndex_ = _getArgUint64(0x5C);
    }

    /// @notice Getter for the extra data.
    /// @dev `clones-with-immutable-args` argument #2
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function extraData() external pure returns (bytes memory extraData_) {
        // The extra data starts at the second word within the cwia calldata and
        // is 32 bytes long.
        extraData_ = _getArgBytes(0x54, 0x10);
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

    // ------------------------------
    // Miscellaneous methods
    // ------------------------------

    /// @notice The parent game contract.
    function parentGame() public view returns (FaultProofGame parentGame_) {
        (GameType parentGameType,, IDisputeGame parentDisputeGame) =
            ANCHOR_STATE_REGISTRY.disputeGameFactory().gameAtIndex(parentGameIndex());

        // Only allow fault claim games to be based off of other instances of the same game type
        if (parentGameType.raw() != GAME_TYPE.raw()) revert GameTypeMismatch(parentGameType, GAME_TYPE);

        // Interpret parent game as another instance of this game type
        parentGame_ = FaultProofGame(address(parentDisputeGame));
    }

    /// @notice Returns the amount of time elapsed on the potential challenger to the claim's chess clock. Maxes
    ///         out at `MAX_CLOCK_DURATION`.
    /// @return duration_ The time elapsed on the potential challenger to `_claimIndex`'s chess clock.
    function getChallengerDuration() public view returns (Duration duration_) {
        // INVARIANT: The game must be in progress to query the remaining time to respond to a given claim.
        if (status != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // Compute the duration elapsed of the potential challenger's clock.
        uint64 challengeDuration = uint64(block.timestamp - createdAt.raw());
        duration_ = challengeDuration > MAX_CLOCK_DURATION.raw() ? MAX_CLOCK_DURATION : Duration.wrap(challengeDuration);
    }

    /// @notice Only the starting block number of the game.
    function startingBlockNumber() external view returns (uint256 startingBlockNumber_) {
        startingBlockNumber_ = parentGame().l2BlockNumber();
    }

    /// @notice Only the starting output root of the game.
    function startingRootHash() external view returns (Hash startingRootHash_) {
        startingRootHash_ = Hash.wrap(parentGame().rootClaim().raw());
    }

    /// @notice Returns the required bond for a challenge.
    /// @return requiredBond_ The required ETH bond in wei.
    function getRequiredBond() public view returns (uint256 requiredBond_) {
        // 2x cheaper to challenge than propose, where x is worst case proving cost
        // challenger of bad proposal will double their money
        // prover of good proposal will be repaid for the validity proof
        requiredBond_ = bond / 2;
    }

    /// @notice Transfers ETH from the contract's balance to the recipient
    function pay(uint256 amount, address recipient) internal {
        (bool success,) = recipient.call{value: amount}(hex"");
        if (!success) revert BondTransferFailed();
    }
}
