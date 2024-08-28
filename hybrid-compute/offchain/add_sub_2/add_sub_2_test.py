from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestAddSub2(a, b):
    print("\n  - - - - TestAddSub2({},{}) - - - -".format(a, b))
    print("TestCount(begin)=", TC.functions.counters(SA.address).call())

    countCall = selector("count(uint32,uint32)") + \
        ethabi.encode(['uint32', 'uint32'], [a, b])

    exCall = selector("execute(address,uint256,bytes)") + \
        ethabi.encode(['address', 'uint256', 'bytes'],
                      [TC.address, 0, countCall])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0: # Estimation failed.
        return

    print("-----")
    submitOp(p)
    print("TestCount(end)=", TC.functions.counters(SA.address).call())
