from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestKyc(aa, isValid: bool):
    print("\n  - - - - TestKyc({}) - - - -".format(isValid))
    print("SA ADDRESS {}".format(SA.address))
    print("TestKyc begin")

    kycCall = None

    if isValid:
        kycCall = selector("openForKyced(string)") + ethabi.encode(['string'], ["0x123"])
    else:
        kycCall = selector("openForKyced(string)") + ethabi.encode(['string'], [""])

    op = aa.build_op(SA.address, KYC.address, 0, kycCall, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("TestKyc end")
