from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestWordGuess(n, cheat):
    print("\n  - - - - TestWordGuess({},{}) - - - -".format(n, cheat))
    gameCall = Web3.to_bytes(hexstr="0x"+selector("wordGuess(string,bool)")) + \
        ethabi.encode(['string', 'bool'], ["frog", cheat])

    perEntry = TC.functions.EntryCost().call()
    print("Pool balance before playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + \
        ethabi.encode(['address', 'uint256', 'bytes'], [
                      TC.address, n * perEntry, gameCall])
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
    print("Pool balance after playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))
