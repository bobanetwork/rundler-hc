#!/usr/bin/python

import os,sys
from web3 import Web3, exceptions
import time
import requests,json
from web3.middleware import geth_poa_middleware
from jsonrpcclient import request, parse, Ok
from eth_abi import abi as ethabi
import eth_account

# ---------------------------------------------------------------------------------------
#
# Global Settings - scroll to the bottom to customize the test contract you're calling.

w3 = Web3(Web3.HTTPProvider("https://gateway.tenderly.co/public/boba-sepolia"))
HC_CHAIN=28882
bundler_rpc = "https://bundler-hc.sepolia.boba.network"

# This is the address of your AA wallet (which must already be initialized) as well as
# the address/privkey of its Owner who can sign user operations for it. 
u_addr = Web3.to_checksum_address(os.environ['CLIENT_ADDR'])
u_owner = Web3.to_checksum_address(os.environ['CLIENT_OWNER'])
u_privkey = os.environ['CLIENT_PRIVKEY']

# ---------------------------------------------------------------------------------------

assert (w3.is_connected)
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

print("gasPrice", w3.eth.gas_price)
print("maxPF", w3.eth.max_priority_fee)


# Entrypoint
EP_addr = Web3.to_checksum_address("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789")

print("Account balance: ", w3.eth.get_balance(u_addr))

def selector(name):
    nameHash = Web3.to_hex(Web3.keccak(text=name))
    return Web3.to_bytes(hexstr=nameHash[:10])

def aa_nonce(addr):
  # sender_nonce = EP.functions.getNonce(u_addr, 0).call()
  calldata = selector("getNonce(address,uint192)") + ethabi.encode(['address','uint192'],[addr, 1234])
  ret = w3.eth.call({'to':EP_addr,'data':calldata})
  return Web3.to_hex(ret)

def buildOp(to_contract, sel_text, payload):
  exCall = selector("execute(address,uint256,bytes)") + \
        ethabi.encode(['address', 'uint256', 'bytes'], [to_contract, 0, selector(sel_text) + payload])
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

def packOp(op):
  ret = (
    op['sender'],
    Web3.to_int(hexstr=op['nonce']),
    op['initCode'],
    Web3.to_bytes(hexstr=op['callData']),
    Web3.to_int(hexstr=op['callGasLimit']),
    Web3.to_int(hexstr=op['verificationGasLimit']),
    Web3.to_int(hexstr=op['preVerificationGas']),
    Web3.to_int(hexstr=op['maxFeePerGas']),
    Web3.to_int(hexstr=op['maxPriorityFeePerGas']),
    op['paymasterAndData'],
    Web3.to_bytes(hexstr=op['signature'])
  )
  return ret

def estimateOp(p):
    gas_total = 0
    est_params = [p, EP_addr]
    print("estimation params {}".format(est_params))
    print()
 
    response = requests.post(
        bundler_rpc, json=request("eth_estimateUserOperationGas", params=est_params))
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
        gas_total = est_result['preVerificationGas'] + est_result['verificationGasLimit'] + est_result['callGasLimit']
    return p, gas_total

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
    
    pack2 = ethabi.encode(['bytes32','address','uint256'], [Web3.keccak(pack1), EP_addr, HC_CHAIN])
    return Web3.keccak(pack2)

def ParseReceipt(opReceipt):
    txRcpt = opReceipt['receipt']

    n = 0
    for i in txRcpt['logs']:
        print("log", n, i['topics'][0], i['data'])
        n += 1
    print("Total tx gas stats:",
        "gasUsed", Web3.to_int(hexstr=txRcpt['gasUsed']),
	"effectiveGasPrice", Web3.to_int(hexstr=txRcpt['effectiveGasPrice']),
	"l1GasUsed", Web3.to_int(hexstr=txRcpt['l1GasUsed']),
	"l1Fee", Web3.to_int(hexstr=txRcpt['l1Fee']))
    opGas = Web3.to_int(hexstr=opReceipt['actualGasUsed'])
    print("opReceipt gas used", opGas)


def submitOp(op):
    eMsg = eth_account.messages.encode_defunct(hash_op(op))
    sig = w3.eth.account.sign_message(eMsg, private_key=u_privkey)
    op['signature'] = Web3.to_hex(sig.signature)
    print("Op to submit:", op)
    print()

    while True:
        response = requests.post(bundler_rpc, json=request(
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
        print("Waiting for receipt...")
        time.sleep(10)
        opReceipt = requests.post(bundler_rpc, json=request(
            "eth_getUserOperationReceipt", params=opHash))
        opReceipt = opReceipt.json()['result']
        if opReceipt is not None:
            # print("opReceipt", opReceipt)
            assert (opReceipt['receipt']['status'] == "0x1")
            print("operation success", opReceipt['success'],
                  "txHash=", opReceipt['receipt']['transactionHash'])
            ParseReceipt(opReceipt)
            timeout = False
            assert (opReceipt['success'])
            break
    if timeout:
        print("*** Previous operation timed out")
        exit(1)

# ------------------------------------------------------------------------------------------------------------------------

# Test configuration - specify the contract and method you wish to call.

# TestCounter.sol
op = buildOp("0x63BceAfAF62fB12394ecbEf10dBF1c5c36ba8b38", "count(uint32,uint32)", ethabi.encode(['uint32', 'uint32'], [4, 1]))

# Translator.sol
#op = buildOp("0xA2b0AD1275f4af175cC96feb63b838bDe25892dd", "do_it(string)", ethabi.encode(['string'], ["send 0.001 ETH to alice.eth"]))

# PresiSimToken.sol (Boyuan)
#op = buildOp("0xa3b4603961e8D1F4a2d98Ff7b28Cf92A6C592441", "getDailyQuestion(string)", ethabi.encode(['string'], ["test"]))


op, gas_est = estimateOp(op)
print("Total gas estimate for op =", gas_est)
submitOp(op)
print("Done")
