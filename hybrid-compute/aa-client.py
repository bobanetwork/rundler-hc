#!/usr/bin/python

import sys
import time
import argparse
import re
import requests
from jsonrpcclient import request
from web3 import Web3
from eth_abi import abi as ethabi

from aa_utils import *

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="Print additional details")
parser.add_argument("--bundler-rpc", required=False, help="URL of the Bundler", default="http://127.0.0.1:3300")
parser.add_argument("--eth-rpc", required=False, help="URL of a replica / sequencer node", default="http://127.0.0.1:9545")
parser.add_argument("--private-key", required=True, help="Private key to sign the operation")
parser.add_argument("--account", required=True, help="Account address")
parser.add_argument("--target", required=True, help="Target contract address")
parser.add_argument("--value", type=int, default=0, help="Value of ETH (in wei) to send with call")
parser.add_argument("--calldata", required=False, default="0x", help="Hex-encoded calldata")
parser.add_argument("--initcode", default="0x", help="Hex-encoded initcode")
parser.add_argument("--entry-point", required=False, help="Override EntryPoint address (or 'detect')")
parser.add_argument("--extra-pvg", default=0, help="Add to estimated preVerificationGas")
parser.add_argument("--ep-version", default="v7", choices=["v6","v7"], help="Specify EntryPoint version (v6 | v7)")
parser.add_argument("--estimate-only", action="store_true", help="Debug option: exit after gas estimation")

args = parser.parse_args()

# "https://gateway.tenderly.co/public/boba-sepolia"
# "https://bundler-hc.sepolia.boba.network"

aa = None

def vprint(*a):
    """Conditionally print console messages"""
    if args.verbose:
        print(*a)

def build_op(to_contract, value_in_wei, initcode_hex, calldata_hex):
    """Wrapper to build a UserOperation"""

    ex_call = selector("execute(address,uint256,bytes)") + \
          ethabi.encode(['address', 'uint256', 'bytes'], [to_contract, value_in_wei, Web3.to_bytes(hexstr=calldata_hex)])

    if args.ep_version == "v7":
        p = {
            'sender':u_addr,
            'nonce': aa.aa_nonce(u_addr, 0),
            'initCode':initcode_hex,
            'callData': Web3.to_hex(ex_call),
            'callGasLimit': "0x0",
            'verificationGasLimit': "0x0",
            'preVerificationGas': "0x0",
            'maxFeePerGas': Web3.to_hex(w3.eth.gas_price),
            'maxPriorityFeePerGas': Web3.to_hex(w3.eth.max_priority_fee),
    #        'paymasterAndData':"0x",
            'signature': '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c'
            }
    else:
        p = {
            'sender':u_addr,
            'nonce': aa.aa_nonce(u_addr, 0),
            'initCode':initcode_hex,
            'callData': Web3.to_hex(ex_call),
            'callGasLimit': "0x0",
            'verificationGasLimit': "0x0",
            'preVerificationGas': "0x0",
            'maxFeePerGas': Web3.to_hex(w3.eth.gas_price),
            'maxPriorityFeePerGas': Web3.to_hex(w3.eth.max_priority_fee),
            'paymasterAndData':"0x",
            'signature': '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c'
            }
    vprint(f"Built op {p} for EP {args.ep_version}")
    return p


def estimate_op(p):
    """Wrapper to estimate gas usage for a UserOperation"""
    gas_total = 0
    est_params = [p, ep_addr]
    vprint(f"estimation params {est_params}")
    vprint()

    response = requests.post(
        args.bundler_rpc, json=request("eth_estimateUserOperationGas", params=est_params), timeout=600)
    try:
        print("estimateGas response", response.json())
    except Exception as e:
        print("*** Can't decode as JSON:", response.text, e)
        sys.exit(1)

    if 'error' in response.json():
        print("*** eth_estimateUserOperationGas failed")
        sys.exit(1)
    else:
        est_result = response.json()['result']
        p['preVerificationGas'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['preVerificationGas']) + args.extra_pvg)
        if 'verificationGasLimit' in est_result:
            p['verificationGasLimit'] = Web3.to_hex(Web3.to_int(
                hexstr=est_result['verificationGasLimit']) + 0)
        else:
            p['verificationGasLimit'] = Web3.to_hex(Web3.to_int(
                hexstr=est_result['verificationGas']) + 0)
        p['callGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['callGasLimit']) + 0)
        gas_total = Web3.to_int(hexstr=est_result['preVerificationGas']) + args.extra_pvg + \
            Web3.to_int(hexstr=est_result['callGasLimit'])
        if 'verificationGasLimit' in est_result:
            gas_total += Web3.to_int(hexstr=est_result['verificationGasLimit'])
        else:
            gas_total += Web3.to_int(hexstr=est_result['verificationGas'])
    return p, gas_total

def submit_op(base_op):
    """Wrapper to sign and submit a UserOperation, waiting for a receipt"""
    if args.ep_version == "v7":
        signed_op = aa.sign_v7_op(base_op, args.private_key)
    else:
        signed_op = aa.sign_op(base_op, args.private_key)

    vprint("Op to submit:", signed_op)
    vprint()

    while True:
        response = requests.post(args.bundler_rpc, json=request(
            "eth_sendUserOperation", params=[signed_op, ep_addr]), timeout=600)
        if 'result' in response.json():
            break
        if 'error' in response.json():
            emsg = response.json()['error']['message']
            if not re.search(r'message: block 0x.{64} not found', emsg): # Workaround for sending debug_traceCall to unsynced node
                break
        print("*** Retrying eth_sendUserOperation")
        time.sleep(5)

    vprint("sendOperation response", response.json())
    if 'error' in response.json():
        print("*** eth_sendUserOperation failed")
        sys.exit(1)

    op_hash = {}
    op_hash['hash'] = response.json()['result']
    timeout = True

    for _ in range(100):
        vprint(f"Waiting for op_hash {op_hash} receipt...")
        time.sleep(10)
        op_receipt = requests.post(args.bundler_rpc, json=request(
            "eth_getUserOperationReceipt", params=[op_hash['hash']]), timeout=600)
        try:
            op_receipt = op_receipt.json()['result']
        except Exception as e:
            print("*** Could not decode receipt:", op_receipt.text, e)
            sys.exit(1)

        if op_receipt is not None:
            #print("op_receipt", op_receipt)
            assert op_receipt['receipt']['status'] == "0x1"
            print(f"operation success={ op_receipt['success']}, txHash={op_receipt['receipt']['transactionHash']}")
            parse_receipt(op_receipt)
            timeout = False
            assert op_receipt['success']
            break
    if timeout:
        print("*** Previous operation timed out")
        sys.exit(1)

def parse_receipt(op_receipt):
    """ Extract log info and gas usage from the receipt"""
    for i in range(100):
        tx_rcpt = w3.eth.get_transaction_receipt(op_receipt['receipt']['transactionHash'])
        if tx_rcpt:
            break
        vprint("Waiting for txReceipt...")
        time.sleep(10)

    n = 0
    for i in tx_rcpt['logs']:
        vprint("log", n, Web3.to_hex(i['topics'][0]), Web3.to_hex(i['data']))
        n += 1
    vprint("Total tx gas stats:")
    vprint("    gasUsed", Web3.to_int(text=tx_rcpt['gasUsed']))
    vprint("effectiveGasPrice", Web3.to_int(text=tx_rcpt['effectiveGasPrice']))
    if 'l1GasUsed' in tx_rcpt:
        vprint("l1GasUsed", Web3.to_int(hexstr=tx_rcpt['l1GasUsed']))
    if 'l1Fee' in tx_rcpt:
        vprint("l1Fee", Web3.to_int(hexstr=tx_rcpt['l1Fee']))
    op_gas = Web3.to_int(hexstr=op_receipt['actualGasUsed'])
    vprint("op_receipt gas used", op_gas)

# ---------------------------------------------------------------------------------------

vprint(f"Will connect to {args.bundler_rpc} (Bundler), {args.eth_rpc} (Eth)")

w3 = Web3(Web3.HTTPProvider(args.eth_rpc))
assert w3.is_connected

# Start with the default addresses
if args.ep_version == "v7":
    ep_addr = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
elif args.ep_version == "v6":
    ep_addr = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

# Allow overrides
if args.entry_point == "detect":
    detect_response = requests.post(
        args.bundler_rpc, json=request("eth_supportedEntryPoints", params=[]), timeout=60)

    assert "result" in detect_response.json()
    ep_list = detect_response.json()['result']
    if len(ep_list) == 1:
        ep_addr = ep_list[0]
        vprint("Detected EntryPoint address", ep_addr)
    else:
        print("Multiple EntryPoints detected, must select one:", ep_list)
        sys.exit(1)
elif args.entry_point:
    ep_addr = Web3.to_checksum_address(args.entry_point)
    print(f"WARN: User forced EntryPoint address {ep_addr}")

if args.ep_version == "v7":
    vprint(f"Using v0.7 EntryPoint address: {ep_addr}")
else:
    vprint(f"Using v0.6 EntryPoint address: {ep_addr}")

aa = aa_rpc(ep_addr, w3, args.bundler_rpc)

vprint("gasPrices", w3.eth.gas_price, w3.eth.max_priority_fee)

owner_wallet = Web3().eth.account.from_key(args.private_key)
u_addr = Web3.to_checksum_address(args.account)
u_owner = owner_wallet.address

acct_balance = w3.eth.get_balance(u_addr)
vprint(f"Using Account contract {u_addr} with owner {u_owner} balance {acct_balance}")

acct_owner_hex = Web3.to_hex(w3.eth.call({'to':u_addr,'data':selector("owner()")}))
acct_owner = Web3.to_checksum_address("0x" + str(acct_owner_hex)[26:])
if acct_owner != u_owner:
    print(f"ERROR: Account owner() {acct_owner} does not match private key for {u_owner}")
    sys.exit(1)

acct_ep_hex = Web3.to_hex(w3.eth.call({'to':u_addr,'data':selector("entryPoint()")}))
acct_ep = Web3.to_checksum_address("0x" + str(acct_ep_hex)[26:])
if acct_ep != ep_addr:
    print(f"ERROR: Account entryPoint() {acct_ep} does not match {ep_addr}")
    sys.exit(1)

if acct_balance < args.value:
    print(f"ERROR: Balance {acct_balance} is less then requested value {args.value}")
    sys.exit(1)

target_addr = Web3.to_checksum_address(args.target)
op = build_op(target_addr, args.value, args.initcode, args.calldata)
op, gas_est = estimate_op(op)
vprint("Total gas estimate for op =", gas_est)
if args.estimate_only:
    print("Exiting after gas estimation")
else:
    submit_op(op)
vprint("Done")
