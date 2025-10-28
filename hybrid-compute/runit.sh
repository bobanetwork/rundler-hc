#!/bin/sh

# Configuration parameters are now taken from environment variables.
# Changes here should be synced with ../docker-wrapper.sh

RUST_BACKTRACE=1 \
  ../target/debug/rundler node \
  --signer.redis_uri=redis://127.0.0.1:6379 \
  --min_stake_value 1000000000000000 \
  --min_unstake_delay 60 \
  --rpc.port 3300 \
  --metrics.port 8380 \
  --pool.chain_poll_interval_millis 500 \
  --builder.max_blocks_to_wait_for_mine 8 \
  --chain_spec ../bin/rundler/chain_specs/boba_sepolia.toml \
  --base_fee_accept_percent 100 \
  $@ 2>&1
