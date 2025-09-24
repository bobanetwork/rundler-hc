import os
from web3 import Web3
from add_sub_2.add_sub_2_offchain import offchain_addsub2
from vrf.vrf_offchain import offchain_random
from ramble.ramble_offchain import offchain_ramble
from check_kyc.check_kyc_offchain import offchain_checkkyc
from get_token_price.get_token_price_offchain import offchain_getprice
from verify_captcha.captcha_offchain import offchain_verifycaptcha
from auction_system.auction_system_offchain import offchain_auction
from sports_betting.sports_betting_offchain import offchain_sports_betting
from rainfall_insurance.rainfall_insurance_offchain import offchain_getrainfall

from hybrid_compute_sdk.server import HybridComputeSDK

PORT = int(os.environ['OC_LISTEN_PORT'])
assert PORT != 0

methods = [
    ("addsub2(uint32,uint32)" ,offchain_addsub2),
    ("ramble(uint256,bool)", offchain_ramble),
    ("checkkyc(string)", offchain_checkkyc),
    ("getprice(string)", offchain_getprice   ),
    ("verifyCaptcha(string,string,string)", offchain_verifycaptcha),
    ("verifyBidder(address)", offchain_auction       ),
    ("get_score(uint256)", offchain_sports_betting),
    ("verifyBidder(address)", offchain_auction,       ),
    ("get_rainfall(string)", offchain_getrainfall,   ),
    ("random(uint256,bytes32)", offchain_random,        ),
]

sdk = HybridComputeSDK()
sdk.create_json_rpc_server_instance('0.0.0.0', PORT)

for m in methods:
    sdk.add_server_action(m[0], m[1])
    print("Registered", sdk.selector(m[0]), m[0])
sdk.serve_forever()
