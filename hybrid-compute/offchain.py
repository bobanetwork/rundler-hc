import os,sys
from web3 import Web3, exceptions
import threading
import signal
import time
#from random import *
import queue
import requests,json
from web3.gas_strategies.time_based import fast_gas_price_strategy
from web3.middleware import geth_poa_middleware
from web3.logs import STRICT, IGNORE, DISCARD, WARN
import logging

from jsonrpcclient import request, parse, Ok
import requests

from eth_abi import abi as ethabi
import eth_account

import rlp
from multiprocessing import Process
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer,SimpleJSONRPCRequestHandler

# HC1 is used by the offchain JSON-RPC endpoint
hc1_addr = Web3.to_checksum_address("0xE073fC0ff8122389F6e693DD94CcDc5AF637448e")
hc1_key  = "0x7c0c629efc797f8c5f658919b7efbae01275470d59d03fdeb0fca1e6bd11d7fa"

# -------------------------------------------------------------

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:9545"))
assert (w3.is_connected)
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
HC_CHAIN=901

with open("./contracts.json","r") as f:
  deployed = json.loads(f.read())

EP = w3.eth.contract(address=deployed['EntryPoint']['address'], abi=deployed['EntryPoint']['abi'])
HH = w3.eth.contract(address=deployed['HCHelper']['address'], abi=deployed['HCHelper']['abi'])
HA = w3.eth.contract(address=deployed['HybridAccount.1']['address'], abi=deployed['HybridAccount.1']['abi'])

# -------------------------------------------------------------

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

# -------------------------------------------------------------

def offchain_addsub2(sk, src_addr, src_nonce, oo_nonce, payload, *args):
  print("  -> offchain_addsub2 handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk, src_addr, src_nonce, oo_nonce, payload, args))
  success = False
  err_code = 1
  resp2 = Web3.to_bytes(text="unknown error")

  try:
    skey = Web3.to_bytes(hexstr=sk)
    srcAddr = Web3.to_checksum_address(src_addr)
    srcNonce = Web3.to_int(hexstr=src_nonce)
    opNonce = Web3.to_int(hexstr=oo_nonce)
    reqBytes = Web3.to_bytes(hexstr=payload)

    dec = ethabi.decode(['uint32','uint32'], reqBytes)

    if dec[0] >= dec[1]:
      s = dec[0] + dec[1]
      d = dec[0] - dec[1]
      resp = ethabi.encode(['uint256','uint256'], [s,d])
      err_code = 0
      success = True
    else:
      print("offchain_addsub2 underflow error", dec[0], dec[1])
      resp = Web3.to_bytes(text="underflow error")
    resp2 = ethabi.encode(['address', 'uint256', 'uint32', 'bytes'], [srcAddr, srcNonce, err_code, resp])
  except Exception as e:
    print("DECODE FAILED", e)

  enc1 = ethabi.encode(['bytes32','bytes'], [skey, resp2])
  p_enc1 = "0xdfc98ae8" + Web3.to_hex(enc1)[2:]

  enc2 = ethabi.encode(['address', 'uint256', 'bytes'], [Web3.to_checksum_address(HH.address), 0, Web3.to_bytes(hexstr=p_enc1)])
  p_enc2 = "0xb61d27f6" + Web3.to_hex(enc2)[2:]

  oo = {
    'sender':HA.address,
    'nonce': Web3.to_hex(opNonce),
    'initCode':'0x',
    'callData': p_enc2,
    'callGasLimit': "0x40000",
    'verificationGasLimit': "0x40000",
    'preVerificationGas': "0x40000",
    'maxFeePerGas': Web3.to_hex(Web3.to_wei(0,'gwei')),
    'maxPriorityFeePerGas': Web3.to_hex(Web3.to_wei(0,'gwei')),
    'paymasterAndData': '0x',
    'signature': '0x'
  }

  ooHash = EP.functions.getUserOpHash(packOp(oo)).call()
  eMsg = eth_account.messages.encode_defunct(ooHash)
  sig = w3.eth.account.sign_message(eMsg, private_key=hc1_key)

  print("Method returning success={} response={} signature={}".format(success, Web3.to_hex(resp), Web3.to_hex(sig.signature)))
  return ({
    "success": success,
    "response": Web3.to_hex(resp),
    "signature": Web3.to_hex(sig.signature)
  })

class RequestHandler(SimpleJSONRPCRequestHandler):
  rpc_paths = ('/', '/hc')

def server_loop():
  #print ("Registering method", contractAddr)
  server = SimpleJSONRPCServer(('192.168.4.2', 1234), requestHandler=RequestHandler)
  server.register_function(offchain_addsub2, "97e0d7ba")
  server.serve_forever()

serverProc = Process(target=server_loop,args=())
serverProc.start()
print("Server started")

time.sleep(86400*10) # Temporary; eventually run forever while waiting for a shutdown signal.

print("You're still here? It's over. Go home.")
serverProc.kill()
