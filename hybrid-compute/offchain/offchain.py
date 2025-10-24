"""Run an offchain Hybrid Compute JSON-RPC server with several examples"""

import os
from dotenv import load_dotenv, find_dotenv
from hybrid_compute_sdk.server import HybridComputeSDK
from web3 import Web3
from eth_abi import abi as ethabi

from add_sub_2.add_sub_2_offchain import offchain_addsub2
from vrf.vrf_offchain import offchain_random
from ramble.ramble_offchain import offchain_ramble
from check_kyc.check_kyc_offchain import offchain_checkkyc
#from get_token_price.get_token_price_offchain import offchain_getprice
#from verify_captcha.captcha_offchain import offchain_verifycaptcha
from auction_system.auction_system_offchain import offchain_auction
from sports_betting.sports_betting_offchain import offchain_sports_betting
#from rainfall_insurance.rainfall_insurance_offchain import offchain_getrainfall

load_dotenv(find_dotenv())

allow_reg = []

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


def server_loop():
    """Register handlers and launch the server"""
    load_dotenv(find_dotenv())
    port = int(os.environ['OC_LISTEN_PORT'])
    assert port != 0

    methods = [
        ("addsub2(uint32,uint32)",  offchain_addsub2),
        ("random(uint256,bytes32)", offchain_random),
        ("ramble(uint256,bool)",    offchain_ramble),
        ("verifyBidder(address)",   offchain_auction),
        ("get_score(uint256)",      offchain_sports_betting),
        ("checkkyc(string)",        offchain_checkkyc),
        #("getprice(string)",        offchain_getprice),
        #("verifyCaptcha(string,string,string)", offchain_verifycaptcha),
        #("get_rainfall(string)",    offchain_getrainfall),
        ("_register(address,string)", sys_register_caller),
    ]

    sdk = HybridComputeSDK()
    sdk.create_json_rpc_server_instance('0.0.0.0', port)

    for m in methods:
        sdk.add_server_action(m[0], m[1])
        print("Registered", sdk.selector(m[0]), m[0])
    sdk.serve_forever()

allow_reg = load_allow_reg()
print("Allowed registration list:", allow_reg)
server_loop()
