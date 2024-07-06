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

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="Print additional details")
parser.add_argument("--bundler-rpc", required=False, help="URL of the Bundler", default="http://127.0.0.1:3300")
parser.add_argument("--eth-rpc", required=False, help="URL of a replica / sequencer node", default="http://127.0.0.1:9545")
parser.add_argument("--private-key", required=True, help="Private key to sign the operation")
parser.add_argument("--account", required=True, help="Account address")
parser.add_argument("--target", required=True, help="Target contract address")
parser.add_argument("--value", type=int, default=0, help="Value of ETH (in wei) to send with call")
parser.add_argument("--calldata", required=True, help="Hex-encoded calldata")

args = parser.parse_args()

# "https://gateway.tenderly.co/public/boba-sepolia"
# "https://bundler-hc.sepolia.boba.network"

def vprint(*a):
  global args
  if args.verbose:
    print(*a)

def selector(name):
    nameHash = Web3.to_hex(Web3.keccak(text=name))
    return Web3.to_bytes(hexstr=nameHash[:10])

def aa_nonce(addr):
  # sender_nonce = EP.functions.getNonce(u_addr, 0).call()
  calldata = selector("getNonce(address,uint192)") + ethabi.encode(['address','uint192'],[addr, 1235])
  ret = w3.eth.call({'to':EP_addr,'data':calldata})
  return Web3.to_hex(ret)

def build_op(to_contract, value_in_wei, calldata_hex):
  exCall = selector("execute(address,uint256,bytes)") + \
        ethabi.encode(['address', 'uint256', 'bytes'], [to_contract, value_in_wei, Web3.to_bytes(hexstr=calldata_hex)])
  p = {
    'sender':u_addr,
    'nonce': aa_nonce(u_addr),
    'initCode':'0x',
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

def hash_op(p):
    pack1 = ethabi.encode(['address','uint256','bytes32','bytes32','uint256','uint256','uint256','uint256','uint256','bytes32'], \
      [p['sender'],
      Web3.to_int(hexstr=p['nonce']),
      Web3.keccak(hexstr=p['initCode']),
      Web3.keccak(hexstr=p['callData']),
      Web3.to_int(hexstr=p['callGasLimit']),
      Web3.to_int(hexstr=p['verificationGasLimit']),
      Web3.to_int(hexstr=p['preVerificationGas']),
      Web3.to_int(hexstr=p['maxFeePerGas']),
      Web3.to_int(hexstr=p['maxPriorityFeePerGas']),
      Web3.keccak(hexstr=p['paymasterAndData']),
      ])

    pack2 = ethabi.encode(['bytes32','address','uint256'], [Web3.keccak(pack1), EP_addr, w3.eth.chain_id])
    return Web3.keccak(pack2)

def estimate_op(p):
    gas_total = 0
    est_params = [p, EP_addr]
    vprint("estimation params {}".format(est_params))
    vprint()
 
    response = requests.post(
        args.bundler_rpc, json=request("eth_estimateUserOperationGas", params=est_params))
    print("estimateGas response", response.json())

    if 'error' in response.json():
        print("*** eth_estimateUserOperationGas failed")
        exit(1)
    else:
        est_result = response.json()['result']
        p['preVerificationGas'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['preVerificationGas']) + 0)
        p['verificationGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['verificationGasLimit']) + 0)
        p['callGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['callGasLimit']) + 0)
        gas_total = Web3.to_int(hexstr=est_result['preVerificationGas']) + \
            Web3.to_int(hexstr=est_result['verificationGasLimit']) + \
            Web3.to_int(hexstr=est_result['callGasLimit'])
    return p, gas_total

def submitOp(op):
    eMsg = eth_account.messages.encode_defunct(hash_op(op))
    sig = w3.eth.account.sign_message(eMsg, private_key=args.private_key)
    op['signature'] = Web3.to_hex(sig.signature)
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

    print("sendOperation response", response.json())
    if 'error' in response.json():
        print("*** eth_sendUserOperation failed")
        exit(1)

    opHash = {}
    opHash['hash'] = response.json()['result']
    timeout = True
    for i in range(100):
        vprint("Waiting for receipt...")
        time.sleep(10)
        opReceipt = requests.post(args.bundler_rpc, json=request(
            "eth_getUserOperationReceipt", params=opHash))
        opReceipt = opReceipt.json()['result']
        if opReceipt is not None:
            # print("opReceipt", opReceipt)
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
    txRcpt = opReceipt['receipt']

    n = 0
    for i in txRcpt['logs']:
        vprint("log", n, i['topics'][0], i['data'])
        n += 1
    vprint("Total tx gas stats:",
        "gasUsed", Web3.to_int(hexstr=txRcpt['gasUsed']),
	"effectiveGasPrice", Web3.to_int(hexstr=txRcpt['effectiveGasPrice']),
	"l1GasUsed", Web3.to_int(hexstr=txRcpt['l1GasUsed']),
	"l1Fee", Web3.to_int(hexstr=txRcpt['l1Fee']))
    opGas = Web3.to_int(hexstr=opReceipt['actualGasUsed'])
    vprint("opReceipt gas used", opGas)

# ---------------------------------------------------------------------------------------

print("Will connect to {} (Bundler), {} (Eth)".format(args.bundler_rpc, args.eth_rpc))

w3 = Web3(Web3.HTTPProvider(args.eth_rpc))
assert (w3.is_connected)
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

response = requests.post(
    args.bundler_rpc, json=request("eth_supportedEntryPoints", params=[]))
assert("result" in response.json())

EP_addr = response.json()['result'][0]

vprint("Detected EntryPoint address", EP_addr)
vprint("gasPrices", w3.eth.gas_price, w3.eth.max_priority_fee)

owner_wallet = Web3().eth.account.from_key(args.private_key)
u_addr = Web3.to_checksum_address(args.account)
u_owner = owner_wallet.address

vprint("Using Account contract {} with owner {} balance {}".format(
    u_addr, u_owner, w3.eth.get_balance(u_addr)))

acct_owner_hex = Web3.to_hex(w3.eth.call({'to':u_addr,'data':selector("owner()")}))
assert(Web3.to_checksum_address("0x" + acct_owner_hex[26:]) == u_owner) # Make sure the account owner is valid

target_addr = Web3.to_checksum_address(args.target)
op = build_op(target_addr, args.value, args.calldata)
op, gas_est = estimate_op(op)
print("Total gas estimate for op =", gas_est)
submitOp(op)
vprint("Done")
