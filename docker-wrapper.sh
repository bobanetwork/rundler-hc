#!/bin/sh
# Wrapper to start a background redis server to support KMS
echo "Launching redis-server"
/usr/bin/redis-server --loglevel notice &
echo "Launching rundler"
/usr/local/bin/rundler node \
  --signer.redis_uri redis://127.0.0.1:6379 \
  --min_stake_value 1000000000000000 \
  --min_unstake_delay 60 \
  $@
