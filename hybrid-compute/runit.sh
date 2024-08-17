#!/bin/sh

# Configuration parameters are now taken from environment variables
RUST_BACKTRACE=1 ETH_POLL_INTERVAL_MILLIS=5000 \
  ../target/debug/rundler node \
  --rpc.port 3300 \
  --builder.private_key $BUILDER_PRIVKEY \
  $@ 2>&1
