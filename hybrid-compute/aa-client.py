#!/usr/bin/python

import os,sys
from web3 import Web3, exceptions
import time
import requests,json
from web3.middleware import geth_poa_middleware
from jsonrpcclient import request, parse, Ok
from eth_abi import abi as ethabi
import eth_account

import argparse
import re

from aa_utils import *

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="Print additional details")
parser.add_argument("--bundler-rpc", required=False, help="URL of the Bundler", default="http://127.0.0.1:3300")
parser.add_argument("--eth-rpc", required=False, help="URL of a replica / sequencer node", default="http://127.0.0.1:9545")
parser.add_argument("--private-key", required=True, help="Private key to sign the operation")
parser.add_argument("--account", required=True, help="Account address")
parser.add_argument("--target", required=True, help="Target contract address")
parser.add_argument("--value", type=int, default=0, help="Value of ETH (in wei) to send with call")
parser.add_argument("--calldata", required=True, help="Hex-encoded calldata")
parser.add_argument("--initcode", default="0x", help="Hex-encoded initcode")
parser.add_argument("--entry-point", required=False, help="EntryPoint address (overrides auto-detection)")
parser.add_argument("--extra-pvg", default=0, help="Add to estimated preVerificationGas")

args = parser.parse_args()

# "https://gateway.tenderly.co/public/boba-sepolia"
# "https://bundler-hc.sepolia.boba.network"

aa = None

def vprint(*a):
  global args
  if args.verbose:
    print(*a)

def build_op(to_contract, value_in_wei, initcode_hex, calldata_hex):
  exCall = selector("execute(address,uint256,bytes)") + \
        ethabi.encode(['address', 'uint256', 'bytes'], [to_contract, value_in_wei, Web3.to_bytes(hexstr=calldata_hex)])
  p = {
    'sender':u_addr,
    'nonce': aa.aa_nonce(u_addr, 1235),
    'initCode':initcode_hex,
    'callData': Web3.to_hex(exCall),
    'callGasLimit': "0x0",
    'verificationGasLimit': Web3.to_hex(0),
    'preVerificationGas': "0x0",
    'maxFeePerGas': Web3.to_hex(w3.eth.gas_price),
    'maxPriorityFeePerGas': Web3.to_hex(w3.eth.max_priority_fee),
    'paymasterAndData':"0x",
    'signature': '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c'
    }
  return p


def estimate_op(p):
    gas_total = 0
    est_params = [p, EP_addr]
    vprint("estimation params {}".format(est_params))
    vprint()
 
    response = requests.post(
        args.bundler_rpc, json=request("eth_estimateUserOperationGas", params=est_params))
    try:
      print("estimateGas response", response.json())
    except:
      print("*** Can't decode as JSON:", response.text)
      exit(1)

    if 'error' in response.json():
        print("*** eth_estimateUserOperationGas failed")
        exit(1)
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

def submitOp(op):
    op = aa.signOp(op)

    vprint("Op to submit:", op)
    vprint()

    while True:
        response = requests.post(args.bundler_rpc, json=request(
            "eth_sendUserOperation", params=[op, EP_addr]))
        if 'result' in response.json():
            break
        elif 'error' in response.json():
            emsg = response.json()['error']['message']
            if not re.search(r'message: block 0x.{64} not found', emsg): # Workaround for sending debug_traceCall to unsynced node
                break
        print("*** Retrying eth_sendUserOperation")
        time.sleep(5)

    vprint("sendOperation response", response.json())
    if 'error' in response.json():
        print("*** eth_sendUserOperation failed")
        exit(1)

    opHash = {}
    opHash['hash'] = response.json()['result']
    timeout = True

    for i in range(100):
        vprint("Waiting for opHash {} receipt...".format(opHash))
        time.sleep(10)
        opReceipt = requests.post(args.bundler_rpc, json=request(
            "eth_getUserOperationReceipt", params=[opHash['hash']]))
        try:
            opReceipt = opReceip0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789t.json()['result']
        except:
            print("*** Could not decode receipt:", opReceipt.text)
            exit(1)

        if opReceipt is not None:
            #print("opReceipt", opReceipt)
            assert (opReceipt['receipt']['status'] == "0x1")
            print("operation success={}, txHash={}".format(
                opReceipt['success'],
                opReceipt['receipt']['transactionHash']))
            ParseReceipt(opReceipt)
            timeout = False
            assert (opReceipt['success'])
            break
    if timeout:
        print("*** Previous operation timed out")
        exit(1)

def ParseReceipt(opReceipt):
    for i in range(100):
        txRcpt = w3.eth.get_transaction_receipt(opReceipt['receipt']['transactionHash'])
        if txRcpt:
            break
        vprint("Waiting for txReceipt...")
        time.sleep(10)

    n = 0
    for i in txRcpt['logs']:
        vprint("log", n, Web3.to_hex(i['topics'][0]), Web3.to_hex(i['data']))
        n += 1
    vprint("Total tx gas stats:",
        "gasUsed", Web3.to_int(text=txRcpt['gasUsed']),
	"effectiveGasPrice", Web3.to_int(text=txRcpt['effectiveGasPrice']),
	"l1GasUsed", Web3.to_int(hexstr=txRcpt['l1GasUsed']),
	"l1Fee", Web3.to_int(hexstr=txRcpt['l1Fee']))
    opGas = Web3.to_int(hexstr=opReceipt['actualGasUsed'])
    vprint("opReceipt gas used", opGas)

# ---------------------------------------------------------------------------------------

vprint("Will connect to {} (Bundler), {} (Eth)".format(args.bundler_rpc, args.eth_rpc))

w3 = Web3(Web3.HTTPProvider(args.eth_rpc))
assert (w3.is_connected)

if args.entry_point:
    EP_addr = Web3.to_checksum_address(args.entry_point)
else:
    response = requests.post(
        args.bundler_rpc, json=request("eth_supportedEntryPoints", params=[]))
    print(response)
    print(response.json())
    assert("result" in response.json())

    EP_addr = response.json()['result'][0]
    vprint("Detected EntryPoint address", EP_addr)

aa = aa_utils(EP_addr, w3.eth.chain_id)

vprint("gasPrices", w3.eth.gas_price, w3.eth.max_priority_fee)

owner_wallet = Web3().eth.account.from_key(args.private_key)
u_addr = Web3.to_checksum_address(args.account)
u_owner = owner_wallet.address

vprint("Using Account contract {} with owner {} balance {}".format(
    u_addr, u_owner, w3.eth.get_balance(u_addr)))

acct_owner_hex = Web3.to_hex(w3.eth.call({'to':u_addr,'data':selector("owner()")}))
assert(Web3.to_checksum_address("0x" + acct_owner_hex[26:]) == u_owner) # Make sure the account owner is valid

target_addr = Web3.to_checksum_address(args.target)
op = build_op(target_addr, args.value, args.initcode, args.calldata)
op, gas_est = estimate_op(op)
vprint("Total gas estimate for op =", gas_est)
submitOp(op)
vprint("Done")
