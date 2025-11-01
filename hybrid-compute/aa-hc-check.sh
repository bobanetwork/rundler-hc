#!/bin/bash
# Script to validate various aspects of a Hybrid Comptute deployment.
set -e

echo "Using environment variables:"
echo "BOBA_TOKEN=$BOBA_TOKEN"
echo "DEPLOY_ADDR=$DEPLOY_ADDR"
echo "CLIENT_ADDR=$CLIENT_ADDR"
echo "NODE_HTTP=$NODE_HTTP"
echo "HC_HELPER_ADDR=$HC_HELPER_ADDR"
echo "OC_HYBRID_ACCOUNT=$OC_HYBRID_ACCOUNT"
echo "TEST_HYBRID=$TEST_HYBRID"

echo
echo "***Checking Client account***"
echo -n "Owner: "
cast call --rpc-url=$NODE_HTTP $CLIENT_ADDR "owner()"
echo -n "ETH Balance: "
cast balance -e --rpc-url=$NODE_HTTP $CLIENT_ADDR
echo -n "BOBA Balance (wei): "
cast call --rpc-url=$NODE_HTTP $BOBA_TOKEN "balanceOf(address)" $CLIENT_ADDR
echo -n "EntryPoint: "
cast call --rpc-url=$NODE_HTTP $CLIENT_ADDR "entryPoint()"

echo
echo "*** Checking HCHelper ***"
echo -n "Owner: "
cast call --rpc-url=$NODE_HTTP $HC_HELPER_ADDR "owner()"
echo -n "ETH Balance: "
cast balance -e --rpc-url=$NODE_HTTP $HC_HELPER_ADDR
echo -n "BOBA Balance (wei): "
cast call --rpc-url=$NODE_HTTP $BOBA_TOKEN "balanceOf(address)" $HC_HELPER_ADDR
echo -n "Price per credit (wei): "
cast call --rpc-url=$NODE_HTTP $HC_HELPER_ADDR "pricePerCall()"

echo "HybridAccount Registration (owner / URL / credits): "
REG=`cast call --rpc-url=$NODE_HTTP $HC_HELPER_ADDR "RegisteredCallers(address)" \
    $OC_HYBRID_ACCOUNT`
cast abi-decode "function()(address,string,uint256)" $REG

# Arbitrary bytes32 key
SOME_B32=0xd80bf0a36ceac0f76e27b53ef27184753b88e8e3964eab6fbfe5783c888e10dc

echo -n "Should be unregistered caller: "
cast call --rpc-url=$NODE_HTTP $HC_HELPER_ADDR \
     --from $CLIENT_ADDR \
     "TryCallOffchain(bytes32,bytes)" $SOME_B32 0x12345678 \
    || true

echo -n "Should be bad encoding: "
cast call --rpc-url=$NODE_HTTP $HC_HELPER_ADDR \
     --from $OC_HYBRID_ACCOUNT \
     "TryCallOffchain(bytes32,bytes)" $SOME_B32 0x123456789A \
    || true

echo -n "Should trigger HC (0x5f48435f54524947...): "
cast call --rpc-url=$NODE_HTTP $HC_HELPER_ADDR \
     --from $OC_HYBRID_ACCOUNT \
     "TryCallOffchain(bytes32,bytes)" $SOME_B32 0x12345678 \
    || true

echo
echo "*** Checking HybridAccount ***"
echo -n "Owner: "
cast call --rpc-url=$NODE_HTTP $OC_HYBRID_ACCOUNT "owner()"
echo -n "ETH Balance: "
cast balance -e --rpc-url=$NODE_HTTP $OC_HYBRID_ACCOUNT
echo -n "BOBA Balance (wei): "
cast call --rpc-url=$NODE_HTTP $BOBA_TOKEN "balanceOf(address)" $OC_HYBRID_ACCOUNT
echo -n "EntryPoint: "
cast call --rpc-url=$NODE_HTTP $OC_HYBRID_ACCOUNT "entryPoint()"
echo -n "Should be Permission denied: "
cast call --rpc-url=$NODE_HTTP $OC_HYBRID_ACCOUNT \
    --from $DEPLOY_ADDR \
    "CallOffchain(bytes32,bytes)" $SOME_B32 0x12345678 \
    || true

echo -n "Should trigger HC (0x5f48435f54524947...): "
cast call --rpc-url=$NODE_HTTP $OC_HYBRID_ACCOUNT \
     --from $TEST_HYBRID \
     "CallOffchain(bytes32,bytes)" $SOME_B32 0x12345678 \
    || true

CD_no_hc=`cast calldata "count(uint32,uint32)" 5 0`
CD_underflow=`cast calldata "count(uint32,uint32)" 3 10`
CD_hc=`cast calldata "count(uint32,uint32)" 2 1`

echo
echo "*** Checking Bundler ***"

echo
echo "Testing gas estimation (non-HC):"
python aa-client.py \
  -v \
  --estimate-only \
  --bundler-rpc $BUNDLER_RPC \
  --eth-rpc $NODE_HTTP \
  --private-key $CLIENT_PRIVKEY \
  --account  $CLIENT_ADDR \
  --target $TEST_HYBRID \
  --calldata $CD_no_hc \
  $@

echo
echo "Testing gas estimation (HC underflow error):"
python aa-client.py \
  -v \
  --estimate-only \
  --bundler-rpc $BUNDLER_RPC \
  --eth-rpc $NODE_HTTP \
  --private-key $CLIENT_PRIVKEY \
  --account  $CLIENT_ADDR \
  --target $TEST_HYBRID \
  --calldata $CD_underflow \
  $@ || true

echo
echo "Testing gas estimation (HC success):"
python aa-client.py \
  -v \
  --estimate-only \
  --bundler-rpc $BUNDLER_RPC \
  --eth-rpc $NODE_HTTP \
  --private-key $CLIENT_PRIVKEY \
  --account  $CLIENT_ADDR \
  --target $TEST_HYBRID \
  --calldata $CD_hc \
  $@

echo "*** Will submit actual userOperation in 5 seconds (ctrl-C to cancel)"
sleep 5

BEFORE=`cast call --rpc-url=$NODE_HTTP $TEST_HYBRID "counters(address)" $CLIENT_ADDR`

python aa-client.py \
  -v \
  --bundler-rpc $BUNDLER_RPC \
  --eth-rpc $NODE_HTTP \
  --private-key $CLIENT_PRIVKEY \
  --account  $CLIENT_ADDR \
  --target $TEST_HYBRID \
  --calldata $CD_hc \
  $@

echo "TestHybrid counter - Before: $BEFORE"
echo -n "TestHybrid counter - After:  "
cast call --rpc-url=$NODE_HTTP $TEST_HYBRID "counters(address)" $CLIENT_ADDR
