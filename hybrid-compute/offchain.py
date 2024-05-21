import os,sys
from web3 import Web3, exceptions
import time

import requests,json
import logging
import requests

from eth_abi import abi as ethabi
import eth_account

from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer,SimpleJSONRPCRequestHandler

HC_CHAIN = int(os.environ['CHAIN_ID'])
assert(HC_CHAIN != 0)

PORT = int(os.environ['OC_LISTEN_PORT'])
assert(PORT != 0)

EP_ADDR = os.environ['ENTRY_POINT']
assert(len(EP_ADDR) == 42)
EntryPointAddr = Web3.to_checksum_address(EP_ADDR)

HH_ADDR = os.environ['HC_HELPER_ADDR']
assert(len(HH_ADDR) == 42)
HelperAddr = Web3.to_checksum_address(HH_ADDR)

HA_ADDR = os.environ['OC_HYBRID_ACCOUNT']
assert(len(HA_ADDR) == 42)
HybridAcctAddr = Web3.to_checksum_address(HA_ADDR)

HA_OWNER = os.environ['OC_OWNER']
assert(len(HA_OWNER) == 42)
hc1_addr = Web3.to_checksum_address(HA_OWNER)

hc1_key = os.environ['OC_PRIVKEY']
assert(len(hc1_key) == 66)

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

  enc2 = ethabi.encode(['address', 'uint256', 'bytes'], [Web3.to_checksum_address(HelperAddr), 0, Web3.to_bytes(hexstr=p_enc1)])
  p_enc2 = "0xb61d27f6" + Web3.to_hex(enc2)[2:]

  oo = {
    'sender':HybridAcctAddr,
    'nonce': Web3.to_hex(opNonce),
    'initCode':'0x',
    'callData': p_enc2,
    'callGasLimit': "0x30000",
    'verificationGasLimit': "0x10000",
    'preVerificationGas': "0x10000",
    'maxFeePerGas': Web3.to_hex(Web3.to_wei(0,'gwei')),
    'maxPriorityFeePerGas': Web3.to_hex(Web3.to_wei(0,'gwei')),
    'paymasterAndData': '0x',
    'signature': '0x'
  }

  p = ethabi.encode([
    'address',
    'uint256',
    'bytes32',
    'bytes32',
    'uint256',
    'uint256',
    'uint256',
    'uint256',
    'uint256',
    'bytes32',
  ],[
    HybridAcctAddr,
    opNonce,
    Web3.keccak(Web3.to_bytes(hexstr='0x')),
    Web3.keccak(Web3.to_bytes(hexstr=p_enc2)),
    Web3.to_int(hexstr=oo['callGasLimit']),
    Web3.to_int(hexstr=oo['verificationGasLimit']),
    Web3.to_int(hexstr=oo['preVerificationGas']),
    Web3.to_int(hexstr=oo['maxFeePerGas']),
    Web3.to_int(hexstr=oo['maxPriorityFeePerGas']),
    Web3.keccak(Web3.to_bytes(hexstr='0x')),
  ])
  ooHash = Web3.keccak(ethabi.encode(['bytes32','address','uint256'],[Web3.keccak(p),EntryPointAddr,HC_CHAIN]))
  signAcct = eth_account.account.Account.from_key(hc1_key)
  eMsg = eth_account.messages.encode_defunct(ooHash)
  sig = signAcct.sign_message(eMsg)

  print("Method returning success={} response={} signature={}".format(success, Web3.to_hex(resp), Web3.to_hex(sig.signature)))
  return ({
    "success": success,
    "response": Web3.to_hex(resp),
    "signature": Web3.to_hex(sig.signature)
  })

class RequestHandler(SimpleJSONRPCRequestHandler):
  rpc_paths = ('/', '/hc')

def server_loop():
  server = SimpleJSONRPCServer(('0.0.0.0', PORT), requestHandler=RequestHandler)
  server.register_function(offchain_addsub2, "97e0d7ba")
  server.serve_forever()

server_loop() # Run until killed
