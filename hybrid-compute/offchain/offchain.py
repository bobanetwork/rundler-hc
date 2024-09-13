import os
from web3 import Web3
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from add_sub_2.add_sub_2_offchain import offchain_addsub2
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


def server_loop():
    """Main loop to listen for and process requests"""
    server = SimpleJSONRPCServer(
        ('0.0.0.0', PORT), requestHandler=RequestHandler)
    server.register_function(offchain_addsub2, selector_hex(
        "addsub2(uint32,uint32)"))  # 97e0d7ba
    server.register_function(
        offchain_ramble,  selector_hex("ramble(uint256,bool)"))
    server.register_function(
        offchain_checkkyc, selector_hex("checkkyc(string)"))
    server.register_function(
        offchain_getprice, selector_hex("getprice(string)"))
    server.register_function(
        offchain_verifycaptcha, selector_hex("verifyCaptcha(string,string,string)"))
    server.register_function(
        offchain_auction, selector_hex("verifyBidder(address)"))
    server.register_function(
        offchain_sports_betting, selector_hex("get_score(uint256)"))
    server.register_function(
        offchain_auction, selector_hex("verifyBidder(address)"))
    server.register_function(
        offchain_getrainfall, selector_hex("get_rainfall(string)"))

    server.serve_forever()

server_loop()  # Run until killed
