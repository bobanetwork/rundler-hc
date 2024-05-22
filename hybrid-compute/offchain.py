import os,sys
from web3 import Web3, exceptions
from eth_abi import abi as ethabi
import eth_account
import requests,json
import logging
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

def selector(name):
  nameHash = Web3.to_hex(Web3.keccak(text=name))
  return nameHash[2:10]

def gen_response(req, err_code, resp_payload):
  resp2 = ethabi.encode(['address', 'uint256', 'uint32', 'bytes'], [req['srcAddr'], req['srcNonce'], err_code, resp_payload])
  enc1 = ethabi.encode(['bytes32','bytes'], [req['skey'], resp2])
  p_enc1 = "0x" + selector("PutResponse(bytes32,bytes)") + Web3.to_hex(enc1)[2:]  # dfc98ae8

  enc2 = ethabi.encode(['address', 'uint256', 'bytes'], [Web3.to_checksum_address(HelperAddr), 0, Web3.to_bytes(hexstr=p_enc1)])
  p_enc2 = selector("execute(address,uint256,bytes)") + Web3.to_hex(enc2)[2:] # b61d27f6

  limits = {
    'callGasLimit': "0x30000",
    'verificationGasLimit': "0x10000",
    'preVerificationGas': "0x10000",
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
    req['opNonce'],
    Web3.keccak(Web3.to_bytes(hexstr='0x')), # initCode
    Web3.keccak(Web3.to_bytes(hexstr=p_enc2)),
    Web3.to_int(hexstr=limits['callGasLimit']),
    Web3.to_int(hexstr=limits['verificationGasLimit']),
    Web3.to_int(hexstr=limits['preVerificationGas']),
    0, # maxFeePerGas
    0, # maxPriorityFeePerGas
    Web3.keccak(Web3.to_bytes(hexstr='0x')), #paymasterANdData
  ])
  ooHash = Web3.keccak(ethabi.encode(['bytes32','address','uint256'],[Web3.keccak(p),EntryPointAddr,HC_CHAIN]))
  signAcct = eth_account.account.Account.from_key(hc1_key)
  eMsg = eth_account.messages.encode_defunct(ooHash)
  sig = signAcct.sign_message(eMsg)

  success = (err_code == 0)
  print("Method returning success={} response={} signature={}".format(success, Web3.to_hex(resp_payload), Web3.to_hex(sig.signature)))
  return ({
    "success": success,
    "response": Web3.to_hex(resp_payload),
    "signature": Web3.to_hex(sig.signature)
  })

  return response

def parse_req(sk, src_addr, src_nonce, oo_nonce, payload):
  req = dict()
  req['skey'] = Web3.to_bytes(hexstr=sk)
  req['srcAddr'] = Web3.to_checksum_address(src_addr)
  req['srcNonce'] = Web3.to_int(hexstr=src_nonce)
  req['opNonce'] = Web3.to_int(hexstr=oo_nonce)
  req['reqBytes'] = Web3.to_bytes(hexstr=payload)
  return req

# -------------------------------------------------------------

# Demo method, given (a,b) returns (a+b , a-b) or an underflow error if b > a
def offchain_addsub2(sk, src_addr, src_nonce, oo_nonce, payload, *args):
  print("  -> offchain_addsub2 handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk, src_addr, src_nonce, oo_nonce, payload, args))
  err_code = 1
  resp = Web3.to_bytes(text="unknown error")

  try:
    req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
    dec = ethabi.decode(['uint32','uint32'], req['reqBytes'])

    if dec[0] >= dec[1]:
      s = dec[0] + dec[1]
      d = dec[0] - dec[1]
      resp = ethabi.encode(['uint256','uint256'], [s,d])
      err_code = 0
    else:
      print("offchain_addsub2 underflow error", dec[0], dec[1])
      resp = Web3.to_bytes(text="underflow error")
  except Exception as e:
    print("DECODE FAILED", e)

  return gen_response(req, err_code, resp)

# -------------------------------------------------------------

class RequestHandler(SimpleJSONRPCRequestHandler):
  rpc_paths = ('/', '/hc')

def server_loop():
  server = SimpleJSONRPCServer(('0.0.0.0', PORT), requestHandler=RequestHandler)
  server.register_function(offchain_addsub2, selector("addsub2(uint32,uint32)"))  # 97e0d7ba
  server.serve_forever()

server_loop() # Run until killed
