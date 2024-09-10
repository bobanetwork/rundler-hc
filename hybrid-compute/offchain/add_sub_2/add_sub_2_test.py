from eth_abi import abi as ethabi
from userop_utils import *

def TestAddSub2(aa, a, b):
    print(f"\n  - - - - TestAddSub2({a},{b}) - - - -")
    print("TestCount(begin)=", TC.functions.counters(SA.address).call())

    count_call = selector("count(uint32,uint32)") + \
        ethabi.encode(['uint32', 'uint32'], [a, b])

    op = aa.build_op(SA.address, TC.address, 0, count_call, nKey)

    (success, op) = estimateOp(aa, op)
    if not success:
        return

    print("-----")
    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)
    print("TestCount(end)=", TC.functions.counters(SA.address).call())
