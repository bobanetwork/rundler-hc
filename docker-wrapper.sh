#!/bin/sh
# Workaround for docker-compose forcing an empty string on an unset var
if [ -z ${SIGNER_PRIVATE_KEYS} ] ; then
  echo "Empty SIGNER_PRIVATE_KEYS, will expect KMS"
  unset SIGNER_PRIVATE_KEYS
fi
# Wrapper to start a background redis server to support KMS
echo "Launching redis-server"
/usr/bin/redis-server --loglevel notice &
echo "Launching rundler"
/usr/local/bin/rundler node \
  --signer.redis_uri redis://127.0.0.1:6379 \
  --min_stake_value 1000000000000000 \
  --min_unstake_delay 60 \
  --base_fee_accept_percent 100 \
  $@
