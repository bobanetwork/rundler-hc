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
    global estGas
    print("\n  - - - - TestAddSub2({},{}) - - - -".format(a, b))
    print("TestCount(begin)=", TC.functions.counters(SA.address).call())

    countCall = Web3.to_bytes(hexstr="0x"+selector("count(uint32,uint32)")
                              ) + ethabi.encode(['uint32', 'uint32'], [a, b])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + \
        ethabi.encode(['address', 'uint256', 'bytes'],
                      [TC.address, 0, countCall])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    j = [p, EP.address]
    response = requests.post(bundler_rpc, json=request(
        "eth_estimateUserOperationGas", params=j), timeout=600)
    print("estimateGas response", response.json())

    if 'error' in response.json():
        print("*** eth_estimateUserOperationGas failed")
        time.sleep(2)
        if True:
            return
        print("*** Continuing after failure")
        p['preVerificationGas'] = "0xffff"
        p['verificationGasLimit'] = "0xffff"
        p['callGasLimit'] = "0x40000"
    else:
        est_result = response.json()['result']

        p['preVerificationGas'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['preVerificationGas']) + 0)
        p['verificationGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['verificationGasLimit']) + 0)
        p['callGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['callGasLimit']) + 0)
        estGas = Web3.to_int(hexstr=est_result['preVerificationGas']) + Web3.to_int(
            hexstr=est_result['verificationGasLimit']) + Web3.to_int(hexstr=est_result['callGasLimit'])
        print("estimateGas total =", estGas)

    print("-----")
    time.sleep(5)
    submitOp(p)
    print("TestCount(end)=", TC.functions.counters(SA.address).call())
