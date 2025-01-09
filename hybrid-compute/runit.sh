#!/bin/sh

# Configuration parameters are now taken from environment variables
RUST_BACKTRACE=1 ETH_POLL_INTERVAL_MILLIS=5000 \
  ../target/debug/rundler node \
  --rpc.port 3300 \
  --metrics.port 8380 \
  --builder.dropped_status_unsupported \
  --min_stake_value 1000000000000000 \
  --min_unstake_delay 60 \
  $@ 2>&1
