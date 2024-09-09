from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *

def TestAddSub2(aa, a, b):
    print("\n  - - - - TestAddSub2({},{}) - - - -".format(a, b))
    print("TestCount(begin)=", TC.functions.counters(SA.address).call())

    count_call = selector("count(uint32,uint32)") + \
        ethabi.encode(['uint32', 'uint32'], [a, b])

    p = aa.build_op(SA.address, TC.address, 0, count_call, nKey)

    p, est = estimateOp(p)
    if est == 0: # Estimation failed.
        return

    print("-----")
    rcpt = aa.sign_submit_op(p, u_key)
    ParseReceipt(rcpt)
    print("TestCount(end)=", TC.functions.counters(SA.address).call())
