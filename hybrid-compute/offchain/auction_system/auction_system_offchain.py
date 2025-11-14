"""Offchain handler for the Hybrid Compute auction-system example"""
from web3 import Web3
from eth_abi import abi as ethabi
from hybrid_compute_sdk.server import HybridComputeSDK

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> verifyBidder(address)")
    return [("verifyBidder(address)",   offchain_auction)]


blacklist = ["0x123"]

def offchain_auction(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """Offchain handler for the Hybrid Compute auction-system example"""
    print(f"  -> offchain_auction handler called with subkey={sk} "
        f"src_addr={src_addr} src_nonce={src_nonce} oo_nonce={oo_nonce} "
        f"payload={payload} extra_args={args}"
    )
    err_code = 0
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()

    try:
        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (wallet_address_to_verify,) = ethabi.decode(['address'], req['reqBytes'])

        print("offchain wallet-address to verify:", wallet_address_to_verify)
        if wallet_address_to_verify in blacklist:
            resp = ethabi.encode(["bool"], [False])
        else:
            resp = ethabi.encode(["bool"], [True])
    except Exception as e:
        resp = ethabi.encode(["bool"], [False])
        err_code = 1
        print("DECODE FAILED", e)

    return sdk.gen_response(req, err_code, resp)
