#!/bin/sh

# Configuration parameters are now taken from environment variables.
# Changes here should be synced with ../docker-wrapper.sh

RUST_BACKTRACE=1 \
  ../target/debug/rundler node \
  --pool.chain_poll_interval_millis 5000 \
  --rpc.port 3300 \
  --metrics.port 8380 \
  --min_stake_value 1000000000000000 \
  --min_unstake_delay 60 \
  --signer.redis_uri=redis://127.0.0.1:6379 \
  $@ 2>&1
