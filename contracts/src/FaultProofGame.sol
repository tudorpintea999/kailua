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

contract FaultProofGame is Clone, IDisputeGame {
    /// @notice Denotes the proven status of the game
    /// @custom:value NONE indicates that no proof has been submitted yet.
    /// @custom:value FAULT indicates that a valid fault proof has been submitted.
    /// @custom:value INTEGRITY indicates that a valid integrity proof has been submitted.
    enum ProofStatus {
        NONE,
        FAULT,
        INTEGRITY
    }

    /// @notice Thrown when a game is initialized for more blocks than the maximum allowed
    error BlockCountExceeded(uint256 l2BlockNumber, uint256 rootBlockNumber);

    /// @notice Thrown when a proof is submitted for an already proven game
    error AlreadyProven();

    /// @notice Emitted when the game is proven.
    /// @param status The proven status of the game
    event Proven(ProofStatus indexed status);

    /// @notice The RISC Zero verifier contract
    IRiscZeroVerifier internal immutable RISC_ZERO_VERIFIER;

    /// @notice The RISC Zero image id of the fault proof program
    bytes32 internal immutable FPVM_IMAGE_ID;

    /// @notice The maximum number of unconfirmed blocks a proposed output may cover
    uint256 internal immutable MAX_BLOCK_COUNT;

    /// @notice The maximum duration that may accumulate on a team's chess clock before they may no longer respond.
    Duration internal immutable MAX_CLOCK_DURATION;

    /// @notice The game type ID
    GameType internal immutable GAME_TYPE;

    /// @notice WETH contract for holding ETH.
    IDelayedWETH internal immutable WETH;

    /// @notice The anchor state registry.
    IAnchorStateRegistry internal immutable ANCHOR_STATE_REGISTRY;

    /// @notice The id of the L2 network this contract argues about.
    uint256 internal immutable L2_CHAIN_ID;

    /// @notice The game type to clone the anchor state from if this game is not set up yet
    GameType internal immutable CLONE_ANCHOR_STATE_GAME_TYPE;

    /// @notice The global root claim's position is always at gindex 1.
    Position internal constant ROOT_POSITION = Position.wrap(1);

    /// @notice The starting timestamp of the game
    Timestamp public createdAt;

    /// @notice The timestamp of the game's global resolution.
    Timestamp public resolvedAt;

    /// @inheritdoc IDisputeGame
    GameStatus public status;

    /// @notice The current proof status of the game.
    ProofStatus public proofStatus;

    /// @notice Flag for the `initialize` function to prevent re-initialization.
    bool internal initialized;

    /// @notice The claim made during the game.
    IFaultDisputeGame.ClaimData public claimData;

    /// @notice The latest finalized output root, serving as the anchor for output derivation.
    OutputRoot public startingOutputRoot;

    /// @notice Semantic version.
    /// @custom:semver 0.1.0
    string public constant version = "0.1.0";

    constructor(
        IRiscZeroVerifier _verifierContract,
        bytes32 _imageId,
        GameType _gameType,
        uint256 _maxBlockCount,
        Duration _maxClockDuration,
        IDelayedWETH _weth,
        IAnchorStateRegistry _anchorStateRegistry,
        uint256 _l2ChainId,
        GameType _cloneAnchorStateGameType
    ) {
        RISC_ZERO_VERIFIER = _verifierContract;
        FPVM_IMAGE_ID = _imageId;
        GAME_TYPE = _gameType;
        MAX_BLOCK_COUNT = _maxBlockCount;
        MAX_CLOCK_DURATION = _maxClockDuration;
        WETH = _weth;
        ANCHOR_STATE_REGISTRY = _anchorStateRegistry;
        L2_CHAIN_ID = _l2ChainId;
        CLONE_ANCHOR_STATE_GAME_TYPE = _cloneAnchorStateGameType;
    }

    /// @notice Initializes the contract
    /// @dev This function may only be called once.
    function initialize() external payable {
        // SAFETY: Any revert in this function will bubble up to the DisputeGameFactory and
        // prevent the game from being created.
        //
        // Implicit assumptions:
        // - The `gameStatus` state variable defaults to 0, which is `GameStatus.IN_PROGRESS`
        // - The dispute game factory will enforce the required bond to initialize the game.
        //
        // Explicit checks:
        // - The game must not have already been initialized.
        // - An output root cannot be proposed at or before the starting block number.

        // INVARIANT: The game must not have already been initialized.
        if (initialized) revert AlreadyInitialized();

        // Grab the latest anchor root.
        (Hash root, uint256 rootBlockNumber) = ANCHOR_STATE_REGISTRY.anchors(GAME_TYPE);
        if (root.raw() == bytes32(0)) {
            (root, rootBlockNumber) = ANCHOR_STATE_REGISTRY.anchors(CLONE_ANCHOR_STATE_GAME_TYPE);
        }

        // Should only happen if this game type and the cloned type haven't been set up yet or the registry wasn't initialized
        if (root.raw() == bytes32(0)) {
            revert AnchorRootNotFound();
        }

        // Set the starting output root.
        startingOutputRoot = OutputRoot({l2BlockNumber: rootBlockNumber, root: root});

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
        // - 0x20 extraData (block number)
        // - 0x02 CWIA bytes
        assembly {
            if iszero(eq(calldatasize(), 0x7A)) {
                // Store the selector for `BadExtraData()` & revert
                mstore(0x00, 0x9824bdab)
                revert(0x1C, 0x04)
            }
        }

        // Do not allow the game to be initialized if the root claim corresponds to a block at or before the
        // configured starting block number.
        if (l2BlockNumber() <= rootBlockNumber) revert UnexpectedRootClaim(rootClaim());

        // Do not initialize a game that covers more blocks than permitted
        if (l2BlockNumber() - rootBlockNumber > MAX_BLOCK_COUNT) {
            revert BlockCountExceeded(l2BlockNumber(), rootBlockNumber);
        }

        // Set the root claim
        claimData = IFaultDisputeGame.ClaimData({
            parentIndex: type(uint32).max,
            counteredBy: address(0),
            claimant: gameCreator(),
            bond: uint128(msg.value),
            claim: rootClaim(),
            position: ROOT_POSITION, // todo: remove this?
            clock: LibClock.wrap(Duration.wrap(0), Timestamp.wrap(uint64(block.timestamp)))
        });

        // Set the game as initialized.
        initialized = true;

        // Deposit the bond.
        WETH.deposit{value: msg.value}();

        // Set the game's starting timestamp
        createdAt = Timestamp.wrap(uint64(block.timestamp));
    }

    /// @notice Proves the integrity of faultiness of the output argued on by this contract
    function prove(bytes calldata proof, bool isFaultProof) public {
        // INVARIANT: Proofs cannot be submitted unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // INVARIANT: Proofs can only be submitted once
        if (proofStatus != ProofStatus.NONE) revert AlreadyProven();

        // Construct the expected journal
        bytes32 journalDigest = sha256(
            abi.encodePacked(
                // The L1 head hash containing the safe L2 chain data that may reproduce the L2 head hash.
                l1Head().raw(),
                // The latest finalized L2 output root.
                startingOutputRoot.root.raw(),
                // The L2 output root claim.
                rootClaim().raw(),
                // The L2 claim block number.
                uint64(l2BlockNumber()),
                // The l2 chain id for this network
                uint64(L2_CHAIN_ID),
                // True iff the proof demonstrates fraud, false iff it demonstrates integrity
                isFaultProof
            )
        );

        // reverts on failure
        RISC_ZERO_VERIFIER.verify(proof, FPVM_IMAGE_ID, journalDigest);

        // Update proof status
        emit Proven(proofStatus = isFaultProof ? ProofStatus.FAULT : ProofStatus.INTEGRITY);

        // Pay out the bond to the fault prover if the output is invalid
        if (isFaultProof) {
            payBond(msg.sender);
        }
    }

    /// @notice If all necessary information has been gathered, this function should mark the game
    ///         status as either `CHALLENGER_WINS` or `DEFENDER_WINS` and return the status of
    ///         the resolved game.
    /// @dev May only be called if the `status` is `IN_PROGRESS`.
    /// @return status_ The status of the game after resolution.
    function resolve() external returns (GameStatus status_) {
        // INVARIANT: Resolution cannot occur unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        // Update status
        if (proofStatus == ProofStatus.NONE) {
            // INVARIANT: Cannot resolve an unproven game unless the clock of its would-be proof has expired
            if (getChallengerDuration().raw() < MAX_CLOCK_DURATION.raw()) revert ClockNotExpired();

            status_ = GameStatus.DEFENDER_WINS;
        } else {
            // Decide winner based on proof validity
            if (proofStatus == ProofStatus.FAULT) {
                status_ = GameStatus.CHALLENGER_WINS;
            } else {
                status_ = GameStatus.DEFENDER_WINS;
            }
        }

        // Pay out the bond to the game creator if integrity was shown
        if (status_ == GameStatus.DEFENDER_WINS) {
            payBond(gameCreator());
        }

        // Mark resolution timestamp
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));

        // Update the status and emit the resolved event, note that we're performing a storage update here.
        emit Resolved(status = status_);

        // Try to update the anchor state, this should not revert.
        ANCHOR_STATE_REGISTRY.tryUpdateAnchorState();
    }

    function payBond(address recipient) internal {
        (bool success,) = recipient.call{value: address(this).balance}(hex"");
        if (!success) revert BondTransferFailed();
    }

    // Init data helpers

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

    /// @notice The l2BlockNumber of the disputed output root in the `L2OutputOracle`.
    function l2BlockNumber() public pure returns (uint256 l2BlockNumber_) {
        l2BlockNumber_ = _getArgUint256(0x54);
    }

    // Storage data helpers

    /// @notice Returns the amount of time elapsed on the potential challenger to the claim's chess clock. Maxes
    ///         out at `MAX_CLOCK_DURATION`.
    /// @return duration_ The time elapsed on the potential challenger to `_claimIndex`'s chess clock.
    function getChallengerDuration() public view returns (Duration duration_) {
        // INVARIANT: The game must be in progress to query the remaining time to respond to a given claim.
        if (status != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // Compute the duration elapsed of the potential challenger's clock.
        uint64 challengeDuration = uint64(block.timestamp - claimData.clock.timestamp().raw());
        duration_ = challengeDuration > MAX_CLOCK_DURATION.raw() ? MAX_CLOCK_DURATION : Duration.wrap(challengeDuration);
    }

    /// @notice Only the starting block number of the game.
    function startingBlockNumber() external view returns (uint256 startingBlockNumber_) {
        startingBlockNumber_ = startingOutputRoot.l2BlockNumber;
    }

    /// @notice Only the starting output root of the game.
    function startingRootHash() external view returns (Hash startingRootHash_) {
        startingRootHash_ = startingOutputRoot.root;
    }

    // Immutable config data helpers

    /// @notice Returns the id of the L2 network this contract argues about.
    function l2ChainId() external view returns (uint256 l2ChainId_) {
        l2ChainId_ = L2_CHAIN_ID;
    }

    /// @notice Returns the anchor state registry contract.
    function anchorStateRegistry() external view returns (IAnchorStateRegistry registry_) {
        registry_ = ANCHOR_STATE_REGISTRY;
    }

    /// @notice Returns the WETH contract for holding ETH.
    function weth() external view returns (IDelayedWETH weth_) {
        weth_ = WETH;
    }

    /// @notice Getter for the game type.
    /// @dev The reference impl should be entirely different depending on the type (fault, validity)
    ///      i.e. The game type should indicate the security model.
    /// @return gameType_ The type of proof system being used.
    function gameType() external view returns (GameType gameType_) {
        gameType_ = GAME_TYPE;
    }

    /// @notice Returns the max clock duration.
    function maxClockDuration() external view returns (Duration maxClockDuration_) {
        maxClockDuration_ = MAX_CLOCK_DURATION;
    }

    /// @notice Returns the maximum number of blocks that can be covered by this game
    function maxBlockCount() external view returns (uint256 maxBlockCount_) {
        maxBlockCount_ = MAX_BLOCK_COUNT;
    }

    /// @notice Returns the RISC Zero Image ID of the FPVM program used by this contract
    function imageId() external view returns (bytes32 imageId_) {
        imageId_ = FPVM_IMAGE_ID;
    }

    /// @notice Returns the address of the RISC Zero verifier used by this contract
    function verifier() external view returns (IRiscZeroVerifier verifier_) {
        verifier_ = RISC_ZERO_VERIFIER;
    }
}
