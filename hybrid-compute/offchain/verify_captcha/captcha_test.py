from web3 import Web3
import redis
import uuid
import base64
from captcha.image import ImageCaptcha

import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestCaptcha(user_addr):
    global estGas
    print("\n  - - - - TestCaptcha({}) - - - -".format(user_addr))
    print("SA ADDRESS {}".format(SA.address))
    print("TestCaptcha begin")

    captcha = get_captcha(user_addr)
    print("captcha")
    print(captcha.uuid_bytes)
    print(captcha.image_str)
    print(captcha.image_data)
    print("==================")

    # user_addr, uuid, input
    captchaCall = Web3.to_bytes(
        hexstr="0x"+selector("verifycaptcha(string,string,string)")) + ethabi.encode(['string', 'string', 'string'],
                                                                                       [user_addr, captcha.uuid_bytes, captcha.image_str])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [TCAPTCHA.address, 0, captchaCall])

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
    print("TestCaptcha end")
    if timeout:
        print("*** Previous operation timed out")
        exit(1)


def get_captcha(user_addr):
    try:
        image = ImageCaptcha(width=280, height=90)
        uuid1 = uuid.uuid4()
        image_str = str(uuid1).split("-")[0]

        image_data = image.generate(image_str)

        uuid2 = uuid.uuid4()

        uuid_bytes = Web3.solidity_keccak(['string'], [str(uuid2)]).hex()
        key_bytes = uuid_bytes + user_addr

        r = redis.Redis(host='localhost', port=6379, db=0)
        # set expire time to 10 minutes
        r.set(key_bytes, image_str, ex=600)


        return Captcha(
            uuid_bytes,
            image_str,
            image_data
        )
    except Exception as e:
        print("Error:", e)
        return Web3.to_bytes(text="Error: {}".format(e))


class Captcha:
    def __init__(self, uuid_bytes, image_str, image_data) -> None:
        self.uuid_bytes = uuid_bytes
        self.image_str = image_str
        self.image_data = image_data
