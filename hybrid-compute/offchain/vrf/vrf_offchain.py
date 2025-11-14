"""
Offchain handler for VRF contract. Implements a Chainlink-style
verifiable random function with an option to XOR a client-supplied
random number.

Reference: https://eprint.iacr.org/2017/099.pdf
"""

import os
from web3 import Web3
from eth_abi import abi as ethabi
from hybrid_compute_sdk.server import HybridComputeSDK

# --------------------------------------
from fastecdsa import curve,keys,util,point
from eth_keys import keys as ethkeys

rand_key_hex = os.environ['OC_RANDOM_SECRET']
oc_node_http = os.environ['OC_NODE_HTTP']

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> random(uint256,bytes32)")
    return [("random(uint256,bytes32)", offchain_random)]

assert len(rand_key_hex) == 66

G = curve.secp256k1.G
FIELD_SIZE = Web3.to_int(hexstr=\
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
GROUP_ORDER = Web3.to_int(hexstr= \
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

def projective_mul(x1, z1, x2, z2):
    """Adapted from Chainlink VRF.sol, function _projectiveMul"""
    x3 = (x1 * x2 ) % FIELD_SIZE
    z3 = (z1 * z2 ) % FIELD_SIZE
    return (x3,z3)

def projective_sub(x1, z1, x2, z2):
    """ Adapted from Chainlink VRF.sol, function _projectiveSub"""
    num1 = (z2 * x1) % FIELD_SIZE
    num2 = ((FIELD_SIZE - x2) * z1) % FIELD_SIZE
    x3 = (num1 + num2) % FIELD_SIZE
    z3 = (z1 * z2) % FIELD_SIZE
    return (x3, z3)

def projective_add(p, q):
    """Adapted from Chainlink VRF.sol, function _projectiveECAdd"""
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
    """Adapted from Chainlink VRF.sol, function _hashToCurve"""
    pre_hash = "0x000000000000000000000000000000000000000000000000000000000000001" + \
               str(Web3.to_hex(p.x))[2:].rjust(64,'0') + \
               str(Web3.to_hex(p.y))[2:].rjust(64,'0') + \
               str(Web3.to_hex(seed_num))[2:].rjust(64,'0')

    cp = new_candidate_point(pre_hash)
    while not curve.secp256k1.is_point_on_curve(cp):
        cp = new_candidate_point(Web3.to_hex(cp[0]))
    return  point.Point(cp[0], cp[1], curve.secp256k1)

def new_candidate_point(hexbytes):
    """Adapted from Chainlink VRF.sol, functions _newCandidateSecp256k1Point and _fieldHash"""
    b = Web3.to_bytes(hexstr=hexbytes)
    # px = _fieldHash(b)
    px = Web3.to_int(Web3.keccak(b))
    while px >= FIELD_SIZE:
        x_hex = str(Web3.to_hex(px))[2:].rjust(64,'0')
        x_bytes = Web3.to_bytes(hexstr="0x"+x_hex)
        px = Web3.to_int(Web3.keccak(x_bytes))

    # py = _squareRoot(_ySquared(px))
    # uint256 xCubed = mulmod(x, mulmod(x, x, FIELD_SIZE), FIELD_SIZE);
    # return addmod(xCubed, 7, FIELD_SIZE);
    x_cubed = (px * px % FIELD_SIZE) * px % FIELD_SIZE
    y_squared = x_cubed + 7 % FIELD_SIZE
    py = util.mod_sqrt(y_squared, FIELD_SIZE)[0]

    if py % 2 == 1:
        py = FIELD_SIZE - py
    return (px, py)

def point_ethereum_address(u):
    """Convert an elliptic curve point to an Ethereum address"""
    u_hex = "0x" + str(Web3.to_hex(u.x))[2:].rjust(64,'0') + \
        str(Web3.to_hex(u.y))[2:].rjust(64,'0')
    u_hash = Web3.keccak(Web3.to_bytes(hexstr=u_hex))
    return "0x" + str(Web3.to_hex(u_hash))[-40:]

def scalar_from_curve_points(h, pk, gamma, u_witness, v):
    """Adapted from Chainlink VRF.sol, function _scalarFromCurvePoints"""
    c_pre_hash = "0x0000000000000000000000000000000000000000000000000000000000000002" + \
                str(Web3.to_hex(h.x))[2:].rjust(64,'0') + \
                str(Web3.to_hex(h.y))[2:].rjust(64,'0') + \
                str(Web3.to_hex(pk.x))[2:].rjust(64,'0') + \
                str(Web3.to_hex(pk.y))[2:].rjust(64,'0') + \
                str(Web3.to_hex(gamma.x))[2:].rjust(64,'0') + \
                str(Web3.to_hex(gamma.y))[2:].rjust(64,'0') + \
                str(Web3.to_hex(v.x))[2:].rjust(64,'0') + \
                str(Web3.to_hex(v.y))[2:].rjust(64,'0') + \
                u_witness[2:]
    c_hex = Web3.to_hex(Web3.keccak(Web3.to_bytes(hexstr=c_pre_hash)))
    return Web3.to_int(hexstr=c_hex)

def make_proof(sk, pk, seed):
    """Construct the VRF proof"""
    proof = {}
    proof['seed'] = seed

    h = hash_to_curve(pk, seed)
    proof['gamma'] = h * sk

    sm = keys.gen_private_key(curve.secp256k1)
    u = G * sm
    proof['uWitness'] = point_ethereum_address(u)

    v = h * sm

    proof['c'] = scalar_from_curve_points(h, pk, proof['gamma'], proof['uWitness'], v)
    #	// (m - c*secretKey) % GroupOrder
    #	s := bm.Mod(bm.Sub(nonce, bm.Mul(c, secretKey)), secp256k1.GroupOrder)
    proof['s'] = (sm - proof['c'] * sk) % GROUP_ORDER

    assert proof['c'] * proof['gamma'] != proof['s'] * h

    # Solidity precalcs
    proof['cGammaWitness'] = proof['c'] * proof['gamma']
    proof['sHashWitness'] = proof['s'] * h

    (_, _, zz) = projective_add(proof['cGammaWitness'], proof['sHashWitness'])
    proof['zInv'] = pow(zz, -1, FIELD_SIZE)  # Python3.8+

    return proof

def output_hash(proof):
    """Adapted from Chainlink VRF.sol, function _randomValueFromVRFProof. This is the VRF output."""
    o_pre_hash = \
        "0x0000000000000000000000000000000000000000000000000000000000000003" + \
        str(Web3.to_hex(proof['gamma'].x))[2:].rjust(64,'0') + \
        str(Web3.to_hex(proof['gamma'].y))[2:].rjust(64,'0')
    o_hash = Web3.keccak(Web3.to_bytes(hexstr=o_pre_hash))
    return Web3.to_hex(o_hash)

def verify_proof(pk, proof):
    """Adapted from Chainlink VRF.sol, function _verifyVRFProof"""
    assert curve.secp256k1.is_point_on_curve((pk.x, pk.y))
    assert curve.secp256k1.is_point_on_curve((proof['gamma'].x, proof['gamma'].y))
    assert curve.secp256k1.is_point_on_curve(
        (proof['cGammaWitness'].x, proof['cGammaWitness'].y)
    )
    assert curve.secp256k1.is_point_on_curve((proof['sHashWitness'].x, proof['sHashWitness'].y))
    # require(_verifyLinearCombinationWithGenerator(c, pk, s, uWitness),
    #     "addr(c*pk+s*g)!=_uWitness");
    parity = pk.y % 2
    pseudo_hash = (- pk.x * proof['s']) % GROUP_ORDER
    pseudo_sig = (proof['c'] * pk.x) % GROUP_ORDER

    ksig = ethkeys.Signature(vrs=(parity, pk.x, pseudo_sig))
    rkey = ksig.recover_public_key_from_msg_hash(Web3.to_bytes(hexstr=Web3.to_hex(pseudo_hash)))
    assert curve.secp256k1.is_point_on_curve(
        (Web3.to_int(hexstr=Web3.to_hex(rkey[:32])),
        Web3.to_int(hexstr=Web3.to_hex(rkey[32:])))
    )
    r_addr = "0x" + str(Web3.to_hex(Web3.keccak(Web3.to_bytes(hexstr=rkey.to_hex()))))[-40:]
    assert r_addr == proof['uWitness']

    h2 = hash_to_curve(pk, proof['seed'])

    # uint256[2] memory v = _linearCombination(c, gamma, cGammaWitness, s, hash, sHashWitness, zInv
    #    require((cp1Witness[0] % FIELD_SIZE) != (sp2Witness[0] % FIELD_SIZE),
    #        "points in sum must be distinct");
    #
    assert proof['gamma'].x % FIELD_SIZE != h2.x % FIELD_SIZE
    #    require(_ecmulVerify(p1, c, cp1Witness), "First mul check failed");
    assert proof['gamma'] * proof['c'] == proof['cGammaWitness']
    #    require(_ecmulVerify(p2, s, sp2Witness), "Second mul check failed");
    assert h2 * proof['s'] == proof['sHashWitness']
    #    return _affineECAdd(cp1Witness, sp2Witness, zInv);
    v = proof['cGammaWitness'] + proof['sHashWitness']

    (_, _, az) = projective_add(proof['cGammaWitness'], proof['sHashWitness'])
    assert (az * proof['zInv']) % FIELD_SIZE == 1

    h = hash_to_curve(pk, proof['seed'])

    dc = scalar_from_curve_points(h, pk, proof['gamma'], proof['uWitness'], v)
    assert proof['c'] == dc

rand_key = Web3.to_int(hexstr=rand_key_hex)
pub_key = G * rand_key
pub_key_hash = Web3.keccak(ethabi.encode(['uint256','uint256'],[pub_key.x,pub_key.y]))

def offchain_random(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """Hybrid Compute offchain handler to generate a random number and accompanying proof"""

    print(f"  -> offchain_random handler called with ver={ver} "
        f"subkey={sk} src_addr={src_addr} src_nonce={src_nonce} "
        f"oo_nonce={oo_nonce} payload={payload} extra_args={args}"
    )
    err_code = 1
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()
    try:
        w3 = Web3(Web3.HTTPProvider(oc_node_http, request_kwargs={'timeout': 900}))
        assert w3.is_connected

        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (bn, req_seed) = ethabi.decode(['uint256', 'bytes32'], req['reqBytes'])

        bh = Web3.to_hex(w3.eth.get_block(bn).hash)

        actual_seed = Web3.to_hex(Web3.keccak(req_seed + Web3.to_bytes(hexstr=bh)))
        proof = make_proof(rand_key, pub_key, Web3.to_int(hexstr=actual_seed))
        verify_proof(pub_key, proof)

        proof['seed'] = Web3.to_int(req_seed) # contract will construct its own actualSeed

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

        err_code = 0

    except Exception as e:
        print("METHOD FAILED", e)
        if "HTTPConnection" in str(e):
            resp = Web3.to_bytes(text="HC01: OC_NODE_HTTP connection failure")

    return sdk.gen_response(req, err_code, resp)
