from eth_abi import abi as ethabi
from userop_utils import *

def TestAddSub2(aa, a, b):
    print(f"\n  - - - - TestAddSub2({a},{b}) - - - -")
    print("TestCount(begin)=", TC.functions.counters(u_account).call())

    count_call = selector("count(uint32,uint32)") + \
        ethabi.encode(['uint32', 'uint32'], [a, b])

    op = aa.build_op(u_account, TC.address, 0, count_call, nKey, PM_ADDR)

    (success, op) = estimateOp(aa, op)
    if not success:
        return

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("TestCount(end)=", TC.functions.counters(u_account).call())

def TestRandomRequest(aa, joint_random):
    print(f"\n  - - - - TestRandomRequest() - - - -")

    clientRandom = Web3.to_int(hexstr="0x0000111100000000000000000000000000000000000000000000000000001111")
    clientHash   = Web3.keccak(ethabi.encode(['uint256'],[clientRandom]))

    if joint_random:
        count_call = selector("requestJointRandomWord(bytes32)") + \
                     ethabi.encode(['bytes32'],[clientHash])
    else:
        count_call = selector("requestRandomWord()")

    op = aa.build_op(u_account, VRF.address, 0, count_call, nKey, PM_ADDR)

    (success, op) = estimateOp(aa, op)
    if not success:
        return

    rcpt = aa.sign_submit_op(op, u_key)
    logs = ParseReceipt(rcpt, Web3.to_int(Web3.keccak(text="RandomRequest(bytes32,address)")))
    rid = Web3.to_bytes(hexstr=logs[0][1])
    print("RID", Web3.to_hex(rid))

    time.sleep(10)
    print()

    if joint_random:
        count_call = selector("revealJointRandomWord(bytes32,uint256)") + \
                     ethabi.encode(['bytes32', 'uint256'], [rid, clientRandom])
    else:
        count_call = selector("revealRandomWord(bytes32)") + \
                     ethabi.encode(['bytes32'], [rid])

    op = aa.build_op(u_account, VRF.address, 0, count_call, nKey, PM_ADDR)

    (success, op) = estimateOp(aa, op)
    if not success:
        return

    rcpt = aa.sign_submit_op(op, u_key)
    logs = ParseReceipt(rcpt, Web3.to_int(hexstr="0xe07ca074488e9cf5d6eceebff847343d15e3cfcf58a1707a9f29f26d9e05c63d"))
    print("Result = ", logs[0][2])
