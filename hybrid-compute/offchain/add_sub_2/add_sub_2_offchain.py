"""
Offchain RPC handler for a simple math example.

Given a pair of UINT32 numbers, returns the sum and difference.
Returns an error if the subtraction underflows.
"""

from web3 import Web3
from eth_abi import abi as ethabi
from hybrid_compute_sdk.server import HybridComputeSDK

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> addsub2(uint32,uint32)")
    return [("addsub2(uint32,uint32)",  offchain_addsub2)]

def offchain_addsub2(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """ Handler called by JSON-RPC server """
    print(
        f"  -> offchain_addsub2 handler called with ver={ver} subkey={sk} "
        f"src_addr={src_addr} src_nonce={src_nonce} oo_nonce={oo_nonce} "
        f"payload={payload} extra_args={args}"
    )
    err_code = 1
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()

    try:
        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (a,b) = ethabi.decode(['uint32', 'uint32'], req['reqBytes'])

        if a >= b:
            s = a + b
            d = a - b
            resp = ethabi.encode(['uint256', 'uint256'], [s, d])
            err_code = 0
        else:
            print("offchain_addsub2 underflow error", a, b)
            resp = Web3.to_bytes(text="underflow error")
    except Exception as e:
        print("DECODE FAILED", e)

    return sdk.gen_response(req, err_code, resp)
