"""Offchain handler for the Hybrid Compute check_kyc example"""
from web3 import Web3
from eth_abi import abi as ethabi
from hybrid_compute_sdk.server import HybridComputeSDK

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> checkkyc(string)")
    return [("checkkyc(string)",        offchain_checkkyc)]

validWallets = ["0x123"]

def offchain_checkkyc(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """Offchain handler for the Hybrid Compute check_kyc example"""
    print(f"  -> offchain_checkkyc handler called with subkey={sk} "
        f"src_addr={src_addr} src_nonce={src_nonce} oo_nonce={oo_nonce} "
        f"payload={payload} extra_args={args}"
    )
    err_code = 0
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()

    try:
        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (wallet_address_to_verify,) = ethabi.decode(['string'], req['reqBytes'])

        print("offchain wallet-address to verify:", wallet_address_to_verify)
        if wallet_address_to_verify in validWallets:
            resp = ethabi.encode(["bool"], [True])
        else:
            resp = ethabi.encode(["bool"], [False])
    except Exception as e:
        resp = ethabi.encode(["bool"], [False])
        err_code = 1
        print("DECODE FAILED", e)

    return sdk.gen_response(req, err_code, resp)
