from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *

def TestAuction():
    print("\n  - - - - TestAuction() - - - -")

    start_auction_call = Web3.to_bytes(
        hexstr="0x"+selector("createAuction(uint256,address)")) + ethabi.encode(['uint256', 'address'], [300, SA.address])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [TEST_AUCTION.address, 0, start_auction_call])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0:  # Estimation failed.
        return

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    submitOp(p)

    bid()
    print("TestAuction end")


def bid():
    print("\n  - - - - bid() - - - -")
    bid_call = Web3.to_bytes(
        hexstr="0x"+selector("bid(uint256)")) + ethabi.encode(['uint256'], [7])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [TEST_AUCTION.address, 6, bid_call])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0:  # Estimation failed.
        return

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    submitOp(p)
    print("TestAuction end")
