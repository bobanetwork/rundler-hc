from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestKyc(isValid: bool):
    print("\n  - - - - TestKyc({}) - - - -".format(isValid))
    print("SA ADDRESS {}".format(SA.address))
    print("TestKyc begin")

    kycCall = None

    if isValid:
        kycCall = Web3.to_bytes(
            hexstr="0x"+selector("openForKyced(string)")) + ethabi.encode(['string'], ["0x123"])
    else:
        kycCall = Web3.to_bytes(
            hexstr="0x"+selector("openForKyced(string)")) + ethabi.encode(['string'], [""])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [KYC.address, 0, kycCall])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0: # Estimation failed.
        return

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    time.sleep(5)
    submitOp(p)
    print("TestKyc end")
