set fallback := true

# default recipe to display help information
default:
  @just --list

build:
  cargo build

devnet-up:
  kurtosis run github.com/ethpandaops/optimism-package --args-file https://raw.githubusercontent.com/ethpandaops/optimism-package/main/network_params.yaml

devnet-down:
  kurtosis clean -a

devnet-deploy l1_rpc l1_beacon_rpc l2_rpc rollup_node_rpc verbosity="":
  ./target/debug/kailua-cli deploy \
      --l1-node-address {{l1_rpc}} \
      --l1-beacon-address {{l1_beacon_rpc}} \
      --l2-node-address {{l2_rpc}} \
      --op-node-address {{rollup_node_rpc}} \
      {{verbosity}}


# Run the client program natively with the host program attached.
prove block_number l1_rpc l1_beacon_rpc l2_rpc rollup_node_rpc data verbosity="":
  #!/usr/bin/env bash

  L1_NODE_ADDRESS="{{l1_rpc}}"
  L1_BEACON_ADDRESS="{{l1_beacon_rpc}}"
  L2_NODE_ADDRESS="{{l2_rpc}}"
  OP_NODE_ADDRESS="{{rollup_node_rpc}}"

  L2_BLOCK_NUMBER={{block_number}}
  echo "Fetching data for block #$L2_BLOCK_NUMBER..."

  # Get output root for block
  L2_CLAIM=$(cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $L2_BLOCK_NUMBER) | jq -r .outputRoot)

  # Get the info for the previous block
  L2_OUTPUT_ROOT=$(cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $((L2_BLOCK_NUMBER - 1))) | jq -r .outputRoot)
  L2_HEAD=$(cast block --rpc-url $L2_NODE_ADDRESS $((L2_BLOCK_NUMBER - 1)) -j | jq -r .hash)
  L1_ORIGIN_NUM=$(cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $((L2_BLOCK_NUMBER - 1))) | jq -r .blockRef.l1origin.number)
  L1_HEAD=$(cast block --rpc-url $L1_NODE_ADDRESS $((L1_ORIGIN_NUM + 50)) -j | jq -r .hash)
  L2_CHAIN_ID=$(cast chain-id --rpc-url $L2_NODE_ADDRESS)

  echo "Running host program with zk client program..."
  ./target/debug/kailua-host \
    --l1-head $L1_HEAD \
    --l2-head $L2_HEAD \
    --l2-claim $L2_CLAIM \
    --l2-output-root $L2_OUTPUT_ROOT \
    --l2-block-number $L2_BLOCK_NUMBER \
    --l2-chain-id $L2_CHAIN_ID \
    --l1-node-address $L1_NODE_ADDRESS \
    --l1-beacon-address $L1_BEACON_ADDRESS \
    --l2-node-address $L2_NODE_ADDRESS \
    --op-node-address $OP_NODE_ADDRESS \
    --exec ./target/debug/kailua-client \
    --data-dir {{data}} \
    {{verbosity}}

prove-devnet block_number data verbosity="":
  #!/usr/bin/env bash

  just prove {{block_number}} http://localhost:8545 http://localhost:5052 http://localhost:9545 http://localhost:7545 {{data}} {{verbosity}}

prove-kurtosis block_number data verbosity="":
  #!/usr/bin/env bash

  just prove {{block_number}} http://127.0.0.1:63638 http://127.0.0.1:63650 http://127.0.0.1:49320 http://127.0.0.1:49383 {{data}} {{verbosity}}

# Show the input args for proving
query block_number l1_rpc l1_beacon_rpc l2_rpc rollup_node_rpc:
  #!/usr/bin/env bash

  L1_NODE_ADDRESS="{{l1_rpc}}"
  L1_BEACON_ADDRESS="{{l1_beacon_rpc}}"
  L2_NODE_ADDRESS="{{l2_rpc}}"
  OP_NODE_ADDRESS="{{rollup_node_rpc}}"

  L2_BLOCK_NUMBER={{block_number}}
  echo "Fetching data for block #$L2_BLOCK_NUMBER..."

  # Get output root for block
  cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $L2_BLOCK_NUMBER) | jq -r .outputRoot

  # Get the info for the previous block
  cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $((L2_BLOCK_NUMBER - 1))) | jq -r .outputRoot
  cast block --rpc-url $L2_NODE_ADDRESS $((L2_BLOCK_NUMBER - 1)) -j | jq -r .hash
  cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $((L2_BLOCK_NUMBER - 1))) | jq -r .blockRef.l1origin.number
  cast block --rpc-url $L1_NODE_ADDRESS $((L1_ORIGIN_NUM + 30)) -j | jq -r .hash
  cast chain-id --rpc-url $L2_NODE_ADDRESS

prove-offline block_number l2_claim l2_output_root l2_head l1_head l2_chain_id data verbosity="":
  #!/usr/bin/env bash

  L2_BLOCK_NUMBER={{block_number}}
  L2_CLAIM={{l2_claim}}
  L2_OUTPUT_ROOT={{l2_output_root}}
  L2_HEAD={{l2_head}}
  L1_HEAD={{l1_head}}
  L2_CHAIN_ID={{l2_chain_id}}

  echo "Running host program with zk client program..."
  ./target/debug/kailua-host \
    --l1-head $L1_HEAD \
    --l2-head $L2_HEAD \
    --l2-claim $L2_CLAIM \
    --l2-output-root $L2_OUTPUT_ROOT \
    --l2-block-number $L2_BLOCK_NUMBER \
    --l2-chain-id $L2_CHAIN_ID \
    --exec ./target/debug/kailua-client \
    --data-dir {{data}} \
    {{verbosity}}

test verbosity="-v":
    #!/usr/bin/env bash

    echo "Rebuilding kailua using cargo"
    just build

    echo "Running cargo tests"
    RISC0_DEV_MODE=1 cargo test

    echo "Running offline proof for op-sepolia block 16491249 (This will take time, and money if RISC0_DEV_MODE is not enabled)"
    RISC0_DEV_MODE=1 just prove-offline 16491249 0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75 0xa548f22e1aa590de7ed271e3eab5b66c6c3db9b8cb0e3f91618516ea9ececde4 0x09b298a83baf4c2e3c6a2e355bb09e27e3fdca435080e8754f8749233d7333b2 0x33a3e5721faa4dc6f25e75000d9810fd6c41320868f3befcc0c261a71da398e1 11155420 ./testdata/16491249 {{verbosity}}

    echo "Cleanup: Removing any .fake receipt files in directory."
    rm ./*.fake
