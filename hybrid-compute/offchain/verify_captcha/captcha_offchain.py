from web3 import Web3
import redis
from eth_abi import abi as ethabi
from offchain_utils import gen_response, parse_req


def offchain_verifycaptcha(sk, src_addr, src_nonce, oo_nonce, payload, *args):
    print("  -> offchain_verifycaptcha handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk,
          src_addr, src_nonce, oo_nonce, payload, args))

    try:
        req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        dec = ethabi.decode(['string', 'string', 'string'], req['reqBytes'])

        user_addr = dec[0]
        uuid_bytes = dec[1]
        captcha_input = dec[2]

        redis = get_redis()
        key_in_redis = redis.get(uuid_bytes + user_addr)

        if key_in_redis:
            is_match = key_in_redis.decode('utf-8') == captcha_input
            print("ismatch ", is_match)
            print('captcha input  ', captcha_input)
            print("key decoded ", key_in_redis.decode('utf-8'))
            return gen_response(req, 0, ethabi.encode(["bool"], [is_match]))
        else:
            return gen_response(req, 1, Web3.to_bytes(text="Error: uuid or to not found"))

    except Exception as e:
        print("Error:", e)


def get_redis():
    return redis.Redis(host='192.168.178.59', port=6379, db=0)
