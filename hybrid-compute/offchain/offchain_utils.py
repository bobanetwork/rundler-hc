import os
import sys
from web3 import Web3
from eth_abi import abi as ethabi
import eth_account

sys.path.append(".") # Workaround until aa_utils etc. can be packaged properly
from aa_utils import *

HC_CHAIN = int(os.environ['CHAIN_ID'])
assert HC_CHAIN != 0

# This var is named "ENTRY_POINTS" to match rundler-hc, however the current
# implementation only supports a single entrypoint.
EP_ADDR = os.environ['ENTRY_POINTS']
assert len(EP_ADDR) == 42
EntryPointAddr = Web3.to_checksum_address(EP_ADDR)

HH_ADDR = os.environ['HC_HELPER_ADDR']
assert len(HH_ADDR) == 42
HelperAddr = Web3.to_checksum_address(HH_ADDR)

HA_ADDR = os.environ['OC_HYBRID_ACCOUNT']
assert len(HA_ADDR) == 42
HybridAcctAddr = Web3.to_checksum_address(HA_ADDR)

HA_OWNER = os.environ['OC_OWNER']
assert len(HA_OWNER) == 42
hc1_addr = Web3.to_checksum_address(HA_OWNER)

hc1_key = os.environ['OC_PRIVKEY']
assert len(hc1_key) == 66

def gen_response(req, err_code, resp_payload):
    resp2 = ethabi.encode(['address', 'uint256', 'uint32', 'bytes'], [
                          req['srcAddr'], req['srcNonce'], err_code, resp_payload])
    p_enc1 = selector("PutResponse(bytes32,bytes)") + \
        ethabi.encode(['bytes32', 'bytes'], [req['skey'], resp2])  # dfc98ae8

    p_enc2 = selector("execute(address,uint256,bytes)") + \
        ethabi.encode(['address', 'uint256', 'bytes'], [
             Web3.to_checksum_address(HelperAddr), 0, p_enc1]) # b61d27f6

    limits = {
        'verificationGasLimit': "0x10000",
        'preVerificationGas': "0x10000",
    }

    # This call_gas formula is a "close enough" estimate for the initial implementation.
    # A more accurate model, or a protocol enhancement to run an actual simulation, may
    # be required in the future.
    call_gas = 705*len(resp_payload) + 170000

    print("call_gas calculation", len(resp_payload), 4+len(p_enc2), call_gas)
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
    ], [
        HybridAcctAddr,
        req['opNonce'],
        Web3.keccak(Web3.to_bytes(hexstr='0x')),  # initCode
        Web3.keccak(p_enc2),
        call_gas,
        Web3.to_int(hexstr=limits['verificationGasLimit']),
        Web3.to_int(hexstr=limits['preVerificationGas']),
        0,  # maxFeePerGas
        0,  # maxPriorityFeePerGas
        Web3.keccak(Web3.to_bytes(hexstr='0x')),  # paymasterAndData
    ])
    oo_hash = Web3.keccak(ethabi.encode(['bytes32', 'address', 'uint256'], [
                         Web3.keccak(p), EntryPointAddr, HC_CHAIN]))
    signer_acct = eth_account.account.Account.from_key(hc1_key)
    e_msg = eth_account.messages.encode_defunct(oo_hash)
    sig = signer_acct.sign_message(e_msg)

    success = (err_code == 0)
    print("Method returning success={} response={} signature={}".format(
        success, Web3.to_hex(resp_payload), Web3.to_hex(sig.signature)))
    return ({
        "success": success,
        "response": Web3.to_hex(resp_payload),
        "signature": Web3.to_hex(sig.signature)
    })

def parse_req(sk, src_addr, src_nonce, oo_nonce, payload):
    req = {}
    req['skey'] = Web3.to_bytes(hexstr=sk)
    req['srcAddr'] = Web3.to_checksum_address(src_addr)
    req['srcNonce'] = Web3.to_int(hexstr=src_nonce)
    req['opNonce'] = Web3.to_int(hexstr=oo_nonce)
    req['reqBytes'] = Web3.to_bytes(hexstr=payload)
    return req
