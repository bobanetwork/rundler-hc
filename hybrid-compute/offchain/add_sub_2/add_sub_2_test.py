""" Calls the offchain AddSub2 method """
from eth_abi import abi as ethabi

def test_add_sub_2(t, a, b, expect_success=True):
    """ Calls the offchain AddSub2 method"""
    test_contract = t.load_contract('TestHybrid')

    print(f"\n  - - - - TestAddSub2({a},{b}) - - - -")
    print("TestCount(begin)=",
        test_contract.functions.counters(t.client_addr).call()
    )

    count_call = t.selector("count(uint32,uint32)") + \
        ethabi.encode(['uint32', 'uint32'], [a, b])

    op = t.build_op('TestHybrid', 0, count_call)

    (success, op) = t.estimate_op(op)
    assert success == expect_success

    if success:
        rcpt = t.submit_op(op)
        t.parse_receipt(rcpt)

    print("TestCount(end)=",
        test_contract.functions.counters(t.client_addr).call()
    )
