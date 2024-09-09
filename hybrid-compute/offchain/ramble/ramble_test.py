from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *

def TestWordGuess(aa, n, cheat):
    print("\n  - - - - TestWordGuess({},{}) - - - -".format(n, cheat))
    game_call = selector("wordGuess(string,bool)") + \
        ethabi.encode(['string', 'bool'], ["frog", cheat])

    per_entry = TC.functions.EntryCost().call()
    print("Pool balance before playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))

    p = aa.build_op(SA.address, TC.address, n * per_entry, game_call, nKey)

    p, est = estimateOp(p)
    assert est != 0

    print("-----")
    rcpt = aa.sign_submit_op(p, u_key)
    ParseReceipt(rcpt)

    print("Pool balance after playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))
