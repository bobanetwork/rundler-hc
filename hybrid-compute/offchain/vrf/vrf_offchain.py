import os
from web3 import Web3
from eth_abi import abi as ethabi
from offchain_utils import gen_response_v7, parse_req

# --------------------------------------
#from web3 import Web3
#eth_abi import abi as ethabi
from fastecdsa import curve,keys,util,point
from eth_keys import keys as ethkeys

rand_key_hex = os.environ['OC_RANDOM_SECRET']
oc_node_http = os.environ['OC_NODE_HTTP']

assert len(rand_key_hex) == 66

G = curve.secp256k1.G
FIELD_SIZE = Web3.to_int(hexstr="0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
GROUP_ORDER = Web3.to_int(hexstr="0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

def projective_mul(x1, z1, x2, z2):
# (x3, z3) = (mulmod(x1, x2, FIELD_SIZE), mulmod(z1, z2, FIELD_SIZE));
    x3 = (x1 * x2 ) % FIELD_SIZE
    z3 = (z1 * z2 ) % FIELD_SIZE
    return (x3,z3)

def projective_sub(x1, z1, x2, z2):
    num1 = (z2 * x1) % FIELD_SIZE
    num2 = ((FIELD_SIZE - x2) * z1) % FIELD_SIZE
    x3 = (num1 + num2) % FIELD_SIZE
    z3 = (z1 * z2) % FIELD_SIZE
    return (x3, z3)

def projective_add(p, q):
    z1 = z2 = 1
    lx = (q.y + FIELD_SIZE - p.y) % FIELD_SIZE
    lz = (q.x + FIELD_SIZE - p.x) % FIELD_SIZE
    (sx, dx) = projective_mul(lx, lz, lx, lz)
    (sx, dx) = projective_sub(sx, dx, p.x, z1)
    (sx, dx) = projective_sub(sx, dx, q.x, z2)
    (sy, dy) = projective_sub(p.x, z1, sx, dx)
    (sy, dy) = projective_mul(sy, dy, lx, lz)
    (sy, dy) = projective_sub(sy, dy, p.y, z1)
    if dx != dy:
        sx = (sx * dy) % FIELD_SIZE
        sy = (sy * dx) % FIELD_SIZE
        sz = (dx * dy) % FIELD_SIZE
    else:
        sz = dx
    return (sx, sy, sz)

def hash_to_curve(p, seed_num):
    pre_hash = "0x000000000000000000000000000000000000000000000000000000000000001" + \
               Web3.to_hex(p.x)[2:].rjust(64,'0') + Web3.to_hex(p.y)[2:].rjust(64,'0') + \
               Web3.to_hex(seed_num)[2:].rjust(64,'0')

    cp = new_candidat_point(pre_hash)
    while not curve.secp256k1.is_point_on_curve(cp):
        #print("Not on curve", cp)
        cp = new_candidat_point(Web3.to_hex(cp[0]))
    return  point.Point(cp[0], cp[1], curve.secp256k1)

def new_candidat_point(hexbytes):
    b = Web3.to_bytes(hexstr=hexbytes)
    # px = _fieldHash(b)
    px = Web3.to_int(Web3.keccak(b))
    #print("px", px)
    while px >= FIELD_SIZE:
        x_hex = Web3.to_hex(px)[2:].rjust(64,'0')
        x_bytes = Web3.to_bytes(hexstr="0x"+x_hex)
        px = Web3.to_int(Web3.keccak(x_bytes))

    # py = _squareRoot(_ySquared(px))
    # uint256 xCubed = mulmod(x, mulmod(x, x, FIELD_SIZE), FIELD_SIZE);
    # return addmod(xCubed, 7, FIELD_SIZE);
    x_cubed = (px * px % FIELD_SIZE) * px % FIELD_SIZE
    y_squared = x_cubed + 7 % FIELD_SIZE
    #print("x_cubed", x_cubed)
    #print("y_squared", x_cubed)
    #print("mod_sqrt",  util.mod_sqrt(y_squared, FIELD_SIZE))
    py = util.mod_sqrt(y_squared, FIELD_SIZE)[0]
    #print("py", py)

    if py % 2 == 1:
        py = FIELD_SIZE - py
    return (px, py)

def point_ethereum_address(u):
    u_hex = "0x" + Web3.to_hex(u.x)[2:].rjust(64,'0') + Web3.to_hex(u.y)[2:].rjust(64,'0')
    #print("u_hex", u_hex)
    u_hash = Web3.keccak(Web3.to_bytes(hexstr=u_hex))
    return "0x" + Web3.to_hex(u_hash)[-40:]

def scalar_from_curve_points(h, pk, gamma, uWitness, v):
    c_pre_hash = "0x0000000000000000000000000000000000000000000000000000000000000002" + \
                Web3.to_hex(h.x)[2:].rjust(64,'0') + Web3.to_hex(h.y)[2:].rjust(64,'0') + \
                Web3.to_hex(pk.x)[2:].rjust(64,'0') + Web3.to_hex(pk.y)[2:].rjust(64,'0') + \
                Web3.to_hex(gamma.x)[2:].rjust(64,'0') + Web3.to_hex(gamma.y)[2:].rjust(64,'0') + \
                Web3.to_hex(v.x)[2:].rjust(64,'0') + Web3.to_hex(v.y)[2:].rjust(64,'0') + \
                uWitness[2:]

    #print("c_pre_hash", c_pre_hash)
    c_hex = Web3.to_hex(Web3.keccak(Web3.to_bytes(hexstr=c_pre_hash)))
    return Web3.to_int(hexstr=c_hex)

def make_proof(sk, pk, seed):
    proof = {}
    proof['seed'] = seed

    h = hash_to_curve(pk, seed)
    #print("h", h)
    proof['gamma'] = h * sk
    #print("gamma", proof['gamma'])

    sm = keys.gen_private_key(curve.secp256k1)
    #sm = Web3.to_int(hexstr="0xdf4db0551a57193aae49cf5d08347cdce8c00ad04501544f81acd8986e243f55")
    u = G * sm
    proof['uWitness'] = point_ethereum_address(u)
    #print("uWitness", proof['uWitness'])

    print("nonce", Web3.to_hex(sm))
    #print("u", u)

    v = h * sm
    #print("v",v)

    proof['c'] = scalar_from_curve_points(h, pk, proof['gamma'], proof['uWitness'], v)
    #print("c", Web3.to_hex(proof['c']))
    #	// (m - c*secretKey) % GroupOrder
    #	s := bm.Mod(bm.Sub(nonce, bm.Mul(c, secretKey)), secp256k1.GroupOrder)
    proof['s'] = (sm - proof['c'] * sk) % GROUP_ORDER
    #print("s", proof['s'])

    assert proof['c'] * proof['gamma'] != proof['s'] * h

    # Solidity precalcs
    proof['cGammaWitness'] = proof['c'] * proof['gamma']
    #print("cGammaWitness", proof['cGammaWitness'])
    proof['sHashWitness'] = proof['s'] * h
    #print("sHashWitness", proof['sHashWitness'])

    (_, _, zz) = projective_add(proof['cGammaWitness'], proof['sHashWitness'])
    proof['zInv'] = pow(zz, -1, FIELD_SIZE)  # Python3.8+
    #print("zInv", Web3.to_hex(proof['zInv']))

    return proof

def output_hash(proof):
    o_pre_hash = "0x0000000000000000000000000000000000000000000000000000000000000003" + \
              Web3.to_hex(proof['gamma'].x)[2:].rjust(64,'0') + Web3.to_hex(proof['gamma'].y)[2:].rjust(64,'0')
    o_hash = Web3.keccak(Web3.to_bytes(hexstr=o_pre_hash))
    #print("o_hash", Web3.to_hex(o_hash))
    return Web3.to_hex(o_hash)

def verify_proof(pk, proof):
    assert curve.secp256k1.is_point_on_curve((pk.x, pk.y))
    assert curve.secp256k1.is_point_on_curve((proof['gamma'].x, proof['gamma'].y))
    assert curve.secp256k1.is_point_on_curve((proof['cGammaWitness'].x, proof['cGammaWitness'].y))
    assert curve.secp256k1.is_point_on_curve((proof['sHashWitness'].x, proof['sHashWitness'].y))
    # require(_verifyLinearCombinationWithGenerator(c, pk, s, uWitness), "addr(c*pk+s*g)!=_uWitness");
    #print("_verifyLinearCombinationWithGenerator", c, pk, s, uWitness)
    parity = pk.y % 2
    #print("Parity", parity)
    pseudo_hash = (- pk.x * proof['s']) % GROUP_ORDER
    #print("pseudo_hash", Web3.to_hex(pseudo_hash))
    pseudo_sig = (proof['c'] * pk.x) % GROUP_ORDER
    #print("pseudo_sig", Web3.to_hex(pseudo_sig))

    ksig = ethkeys.Signature(vrs=(parity, pk.x, pseudo_sig))
    #print ("ksig", ksig)
    rkey = ksig.recover_public_key_from_msg_hash(Web3.to_bytes(hexstr=Web3.to_hex(pseudo_hash)))
    #print("rkey", rkey.to_hex())
    assert curve.secp256k1.is_point_on_curve((Web3.to_int(hexstr=Web3.to_hex(rkey[:32])), Web3.to_int(hexstr=Web3.to_hex(rkey[32:]))))
    r_addr = "0x" + Web3.to_hex(Web3.keccak(Web3.to_bytes(hexstr=rkey.to_hex())))[-40:]
    #print("r_addr", r_addr)
    #print("uWitness",  proof['uWitness'])
    assert r_addr == proof['uWitness']

    h2 = hash_to_curve(pk, proof['seed'])
    #print("h2", h2)

    # uint256[2] memory v = _linearCombination(c, gamma, cGammaWitness, s, hash, sHashWitness, zInv
    #    require((cp1Witness[0] % FIELD_SIZE) != (sp2Witness[0] % FIELD_SIZE), "points in sum must be distinct");
    assert proof['gamma'].x % FIELD_SIZE != h2.x % FIELD_SIZE
    #    require(_ecmulVerify(p1, c, cp1Witness), "First mul check failed");
    assert proof['gamma'] * proof['c'] == proof['cGammaWitness']
    #    require(_ecmulVerify(p2, s, sp2Witness), "Second mul check failed");
    assert h2 * proof['s'] == proof['sHashWitness']
    #    return _affineECAdd(cp1Witness, sp2Witness, zInv);
    v = proof['cGammaWitness'] + proof['sHashWitness']
    #print("V", v)
    #print("sum", proof['cGammaWitness'] + proof['sHashWitness'])

    (_, _, az) = projective_add(proof['cGammaWitness'], proof['sHashWitness'])
    assert (az * proof['zInv']) % FIELD_SIZE == 1

    h = hash_to_curve(pk, proof['seed'])

    dc = scalar_from_curve_points(h, pk, proof['gamma'], proof['uWitness'], v)
    #print("dc", Web3.to_hex(dc))
    assert proof['c'] == dc

rand_key = Web3.to_int(hexstr=rand_key_hex)
#print("privkey", Web3.to_hex(rand_key))
pub_key = G * rand_key
pub_key_hash = Web3.keccak(ethabi.encode(['uint256','uint256'],[pub_key.x,pub_key.y]))
#print("pub_key", pub_key.x, pub_key.y)
print("pub_key_hash", Web3.to_hex(pub_key_hash))

if False:
    test_seed = Web3.to_int(hexstr="0x728f4b907b3b56106b1f90031e94e172d04d341bf9844a0ce9a4dd0bbf28380")
    print("\ntest_seed", Web3.to_hex(test_seed))
    test_proof = make_proof(rand_key, pub_key, test_seed)
    print("test_proof", test_proof)
    verify_proof(pub_key, test_proof)
    print("test_proof verified OK, output hash =", output_hash(test_proof))
def offchain_random(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    print("  -> offchain_random handler called with ver={} subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(
        ver, sk, src_addr, src_nonce, oo_nonce, payload, args))
    err_code = 1
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"

    try:
        w3 = Web3(Web3.HTTPProvider(oc_node_http, request_kwargs={'timeout': 900}))
        assert w3.is_connected

        req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        dec = ethabi.decode(['uint256', 'bytes32'], req['reqBytes'])

        bn = dec[0]
        req_seed = Web3.to_hex(dec[1])

        bh = Web3.to_hex(w3.eth.get_block(bn).hash)
        print("Block", bn, "Hash", bh, "req_seed", req_seed)

        #rand_seed = Web3.to_int(hexstr="0x728f4b907b3b56106b1f90031e94e172d04d341bf9844a0ce9a4dd0bbf28380")

        actual_seed = Web3.to_hex(Web3.keccak(Web3.to_bytes(hexstr = req_seed + bh[2:])))
        print("actual_seed", actual_seed)
        proof = make_proof(rand_key, pub_key, Web3.to_int(hexstr=actual_seed))
        verify_proof(pub_key, proof)
        #print("PROOF", proof)

        proof['seed'] = Web3.to_int(hexstr=req_seed) # contract will construct its own actualSeed
        print("proof output hash", output_hash(proof))

        resp = ethabi.encode([
          'uint256[2]',
          'uint256[2]',
          'uint256',
          'uint256',
          'uint256',
          'address',
          'uint256[2]',
          'uint256[2]',
          'uint256'
        ],[
          [pub_key.x,pub_key.y],
          [proof['gamma'].x,proof['gamma'].y],
          proof['c'],
          proof['s'],
          proof['seed'],
          proof['uWitness'],
          [proof['cGammaWitness'].x, proof['cGammaWitness'].y],
          [proof['sHashWitness'].x, proof['sHashWitness'].y],
          proof['zInv']
        ])

        print("ENC", Web3.to_hex(resp))

        err_code = 0

    except Exception as e:
        print("METHOD FAILED", e)
        if "HTTPConnection" in str(e):
            resp = Web3.to_bytes(text="HC01: OC_NODE_HTTP connection failure")

    return gen_response_v7(req, err_code, resp)
