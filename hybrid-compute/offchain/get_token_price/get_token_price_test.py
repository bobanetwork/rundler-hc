from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestTokenPrice(aa, tokenSymbol):
    print("\n  - - - - TestTokenPrice({}) - - - -".format(tokenSymbol))

    calldata = selector("fetchPrice(string)") + \
        ethabi.encode(['string'], [tokenSymbol])

    op = aa.build_op(SA.address, TFP.address, 0, calldata, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    topic = Web3.keccak(text="PriceQuote(string,string)")
    event = ParseReceipt(rcpt, topic)
    (token, price) = ethabi.decode(['string', 'string'], Web3.to_bytes(hexstr=event[1]))
    print(f"TestTokenPrice result: {token} = {price}")
