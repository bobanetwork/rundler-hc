""" Tests the VRF contract """
import time
from eth_abi import abi as ethabi
from web3 import Web3
from hybrid_compute_sdk.aa_client import selector

def test_random_request(t, joint_random):
    """ Tests the VRF contract """
    print("\n  - - - - TestRandomRequest() - - - -")

    client_random = Web3.to_int(hexstr=\
        "0x0000111100000000000000000000000000000000000000000000000000001111")
    client_hash   = Web3.keccak(ethabi.encode(['uint256'],[client_random]))

    if joint_random:
        count_call = selector("requestJointRandomWord(bytes32)") + \
                     ethabi.encode(['bytes32'],[client_hash])
    else:
        count_call = selector("requestRandomWord()")

    op = t.build_op('TestRandom', 0, count_call)

    (success, op) = t.estimate_op(op)
    if not success:
        return

    rcpt = t.submit_op(op)
    logs = t.parse_receipt(rcpt, Web3.keccak(text="RandomRequest(bytes32,address)"))
    rid = Web3.to_bytes(hexstr=logs[0][1])
    print("RID", Web3.to_hex(rid))

    time.sleep(10)
    print()

    if joint_random:
        count_call = selector("revealJointRandomWord(bytes32,uint256)") + \
                     ethabi.encode(['bytes32', 'uint256'], [rid, client_random])
    else:
        count_call = selector("revealRandomWord(bytes32)") + \
                     ethabi.encode(['bytes32'], [rid])

    op = t.build_op('TestRandom', 0, count_call)

    (success, op) = t.estimate_op(op)
    if not success:
        return

    rcpt = t.submit_op(op)
    logs = t.parse_receipt(rcpt, Web3.keccak(text="RandomResult(bytes32,uint256)"))
    print("Result = ", logs[0][2])
