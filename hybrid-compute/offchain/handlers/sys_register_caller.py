"""
Offchain handler to support HybridCompute auto-registration protocol
"""

import os
from web3 import Web3

allow_reg = []

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> _register(address,string)")
    return [("_register(address,string)", sys_register_caller)]


def load_allow_reg():
    """ Load a list of accounts permitted to register this server """
    allow_reg_list = ""
    if 'OC_ALLOW_REG' in os.environ:
        allow_reg_list = os.environ['OC_ALLOW_REG']
    if allow_reg_list == "Any":
        # Special case for dev/test
        allow_reg.append("Any")
    elif allow_reg_list:
        for a in allow_reg_list.split():
            assert a == Web3.to_checksum_address(a)
            allow_reg.append(a)
    return allow_reg_list

def sys_register_caller(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """ Handler called by JSON-RPC server """
    print(
        f"  -> register_caller handler called with ver={ver} subkey={sk} "
        f"src_addr={src_addr} src_nonce={src_nonce} oo_nonce={oo_nonce} "
        f"payload={payload} extra_args={args}"
    )
    err_code = 1
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()

    try:
        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (addr,url) = ethabi.decode(['address','string'], req['reqBytes'])

        print("Registration request for", addr, url)
        err_code = 0

        if Web3.to_checksum_address(addr) in allow_reg or "Any" in allow_reg:
            resp_ok = True
        else:
            print(f"WARN Rejecting registration request for {addr}->{url}")
            resp_ok = False
        resp = ethabi.encode(['bool'], [resp_ok])
    except Exception as e:
        print("DECODE FAILED", e)

    return sdk.gen_response(req, err_code, resp)

allow_reg = load_allow_reg()
print("Allowed registration list:", allow_reg or "[]")
