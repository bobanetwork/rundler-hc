from web3 import Web3
from eth_abi import abi as ethabi
from offchain_utils import gen_response, parse_req

validWallets = ["0x123"]

def offchain_checkkyc(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    print("  -> offchain_checkkyc handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk,
          src_addr, src_nonce, oo_nonce, payload, args))
    err_code = 0
    resp = Web3.to_bytes(text="unknown error")
    assert(ver == "0.2")

    try:
        req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        dec = ethabi.decode(['string'], req['reqBytes'])

        walletAddressToVerify = dec[0]
        print("offchain wallet-address to verify:", walletAddressToVerify)
        if walletAddressToVerify in validWallets:
            resp = ethabi.encode(["bool"], [True])
        else:
            resp = ethabi.encode(["bool"], [False])
    except Exception as e:
        resp = ethabi.encode(["bool"], [False])
        err_code = 1
        print("DECODE FAILED", e)

    return gen_response(req, err_code, resp)
