"""Test the Hybrid Compute check_kyc example"""
from eth_abi import abi as ethabi

def test_kyc(t, is_valid: bool):
    """Test the Hybrid Compute check_kyc example"""
    print(f"\n  - - - - TestKyc({is_valid}) - - - -")
    t.load_contract('TestKyc')

    kyc_call = None

    if is_valid:
        kyc_call = t.selector("openForKyced(string)") + ethabi.encode(['string'], ["0x123"])
    else:
        kyc_call = t.selector("openForKyced(string)") + ethabi.encode(['string'], [""])

    op = t.build_op('TestKyc', 0, kyc_call)

    (success, op) = t.estimate_op(op)
    assert success == is_valid

    if success:
        rcpt = t.submit_op(op)
        t.parse_receipt(rcpt)

    print(f"TestKyc end (success {success})")
