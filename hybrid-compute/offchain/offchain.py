"""Run an offchain Hybrid Compute JSON-RPC server with several examples"""

import os
from dotenv import load_dotenv, find_dotenv
from hybrid_compute_sdk.server import HybridComputeSDK

from add_sub_2.add_sub_2_offchain import offchain_addsub2
from vrf.vrf_offchain import offchain_random
from ramble.ramble_offchain import offchain_ramble
from check_kyc.check_kyc_offchain import offchain_checkkyc
#from get_token_price.get_token_price_offchain import offchain_getprice
#from verify_captcha.captcha_offchain import offchain_verifycaptcha
from auction_system.auction_system_offchain import offchain_auction
from sports_betting.sports_betting_offchain import offchain_sports_betting
#from rainfall_insurance.rainfall_insurance_offchain import offchain_getrainfall


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
    ]

    sdk = HybridComputeSDK()
    sdk.create_json_rpc_server_instance('0.0.0.0', port)

    for m in methods:
        sdk.add_server_action(m[0], m[1])
        print("Registered", sdk.selector(m[0]), m[0])
    sdk.serve_forever()

server_loop()
