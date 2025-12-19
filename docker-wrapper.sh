#!/bin/sh
# Workaround for docker-compose forcing an empty string on an unset var
if [ -z ${SIGNER_PRIVATE_KEYS} ] ; then
  echo "Empty SIGNER_PRIVATE_KEYS, will expect KMS"
  unset SIGNER_PRIVATE_KEYS
fi

if [ -z ${HC_HELPER_ADDR} ] ; then
  # This is used for the Compliance tests
  echo "Empty HC_HELPER_ADDR, starting as non-HC"
  /usr/local/bin/rundler $@
else
  # Wrapper to start a background redis server to support KMS
  echo "Launching redis-server for HC bundler"
  /usr/bin/redis-server --loglevel notice &
  echo "Launching rundler with HC"
  /usr/local/bin/rundler node \
    --signer.redis_uri redis://127.0.0.1:6379 \
    --min_stake_value 1000000000000000 \
    --min_unstake_delay 60 \
    --base_fee_accept_percent 100 \
    $@
fi
