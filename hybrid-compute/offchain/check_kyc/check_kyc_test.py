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
    global estGas
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

    j = [p, EP.address]
    print("ep address {}".format(EP.address))
    print("j param {}".format(j))
    response = requests.post(
        "http://localhost:3300/", json=request("eth_estimateUserOperationGas", params=j))
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
    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    time.sleep(5)
    response = requests.post(
        "http://localhost:3300/", json=request("eth_sendUserOperation", params=[p, EP.address]))
    print("sendOperation response", response.json())

    opHash = {}
    opHash['hash'] = response.json()['result']
    timeout = True
    for i in range(10):
        print("Waiting for receipt...")
        time.sleep(1)
        opReceipt = requests.post(
            "http://localhost:3300/", json=request("eth_getUserOperationReceipt", params=opHash))
        opReceipt = opReceipt.json()['result']
        if opReceipt is not None:
            # print("opReceipt", opReceipt)
            assert (opReceipt['receipt']['status'] == "0x1")
            print("operation success", opReceipt['success'])
            ParseReceipt(opReceipt)
            timeout = False
            break
    print("TestKyc end")
    if timeout:
        print("*** Previous operation timed out")
        exit(1)
