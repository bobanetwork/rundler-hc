#!/bin/sh

# Configuration parameters are now taken from environment variables
RUST_BACKTRACE=1 ETH_POLL_INTERVAL_MILLIS=5000 \
  ../target/debug/rundler node \
  --rpc.port 3300 \
  --metrics.port 8380 \
  --builder.private_keys $BUILDER_PRIVKEY \
  --disable_entry_point_v0_7 \
  --builder.dropped_status_unsupported \
  $@ 2>&1
