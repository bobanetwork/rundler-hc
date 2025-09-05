import os
from web3 import Web3
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from add_sub_2.add_sub_2_offchain import offchain_addsub2
from vrf.vrf_offchain import offchain_random
from ramble.ramble_offchain import offchain_ramble
from check_kyc.check_kyc_offchain import offchain_checkkyc
from get_token_price.get_token_price_offchain import offchain_getprice
from verify_captcha.captcha_offchain import offchain_verifycaptcha
from auction_system.auction_system_offchain import offchain_auction
from sports_betting.sports_betting_offchain import offchain_sports_betting
from rainfall_insurance.rainfall_insurance_offchain import offchain_getrainfall

PORT = int(os.environ['OC_LISTEN_PORT'])
assert PORT != 0

def selector_hex(name):
    """Return a Solidity-style function selector as hex digits"""
    name_hash = Web3.to_hex(Web3.keccak(text=name))
    return str(name_hash)[2:10]

class RequestHandler(SimpleJSONRPCRequestHandler):
    rpc_paths = ('/', '/hc')

methods = [
    (offchain_addsub2,       "addsub2(uint32,uint32)"),
    (offchain_ramble,        "ramble(uint256,bool)"),
    (offchain_checkkyc,      "checkkyc(string)"),
    (offchain_getprice,      "getprice(string)"),
    (offchain_verifycaptcha, "verifyCaptcha(string,string,string)"),
    (offchain_auction,       "verifyBidder(address)"),
    (offchain_sports_betting,"get_score(uint256)"),
    (offchain_auction,       "verifyBidder(address)"),
    (offchain_getrainfall,   "get_rainfall(string)"),
    (offchain_random,        "random(uint256,bytes32)"),
]

def list_methods(*args):
    ret = []
    for m in methods:
        ret.append((selector_hex(m[1]), m[1]))
    return ret

def server_loop():
    """Main loop to listen for and process requests"""
    server = SimpleJSONRPCServer(
        ('0.0.0.0', PORT), requestHandler=RequestHandler)

    for m in methods:
        server.register_function(m[0], selector_hex(m[1]))
        print("Registered", selector_hex(m[1]), m[1])
    server.register_function(list_methods, "methods")
    server.serve_forever()

server_loop()  # Run until killed
