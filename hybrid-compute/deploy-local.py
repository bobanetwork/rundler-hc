import os
import json
import time
import re
import subprocess
import socket
import argparse
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_abi import abi as ethabi

from aa_utils import *

env_vars = {}
aa = None
boba_token = None

parser = argparse.ArgumentParser()
parser.add_argument("--boba-path", required=True, help="Path to your local Boba/Optimism repository")
parser.add_argument("--deploy-salt", required=False, help="Salt value for contract deployment", default="0")

cli_args = parser.parse_args()

with open(cli_args.boba_path + "/.devnet/addresses.json", "r", encoding="ascii") as f:
    jj = json.load(f)
    boba_l1_addr = Web3.to_checksum_address(jj['BOBA'])
    bridge_addr  = Web3.to_checksum_address(jj['L1StandardBridgeProxy'])
    portal_addr  = Web3.to_checksum_address(jj['OptimismPortalProxy'])

with open(cli_args.boba_path + "/op-service/predeploys/addresses.go", "r", encoding="ascii") as f:
    for line in f.readlines():
        if re.search("BobaL2 = ", line):
            boba_token = Web3.to_checksum_address(line.split('"')[1])

print("Loaded devnet config:")
print("  BOBA L1", boba_l1_addr)
print("  Bridge", bridge_addr)
print("  BOBA L2", boba_token)

# local.env contains fixed configuration for the local devnet. Additional env variables are
# generated dynamically when contracts are deployed. Do not use any of the local addr/privkey
# accounts on public networks.
print("Reading local.env")
with open("local.env", "r", encoding="ascii") as f:
    for line in f.readlines():
        k,v = line.strip().split('=')
        env_vars[k] = v

deploy_addr = env_vars['DEPLOY_ADDR']
deploy_key = env_vars['DEPLOY_PRIVKEY']

# Get the local IP (not localhost) of this machine
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("192.0.2.0", 1))
local_ip = s.getsockname()[0]
s.close()

l1 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert l1.is_connected
l1.middleware_onion.inject(geth_poa_middleware, layer=0)

w3 = Web3(Web3.HTTPProvider(env_vars['NODE_HTTP']))
assert w3.is_connected

l1_util = eth_utils(l1)
l2_util = eth_utils(w3)

contract_info = {}
OUT_PREFIX = "../crates/types/contracts/out/"

def load_contract(w, name, path, address):
    """Loads a contract's JSON ABI"""
    with open(path, "r") as f:
        j = json.loads(f.read())

    contract_info[name] = {}

    contract_info[name]['abi'] = j['abi']

    deployed[name] = {}
    deployed[name]['abi'] = contract_info[name]['abi']
    deployed[name]['address'] = address

    return w.eth.contract(abi=contract_info[name]['abi'], address=address)


def submit_as_op(addr, calldata, signer_key):
    """Wrapper to build and submit a UserOperation directly to the int. We don't
       have a Bundler to run gas estimation so the values are hard-coded. It might be
       necessary to change these values e.g. if simulating different L1 prices on the local devnet"""
    op = {
        'sender':addr,
        'nonce': aa.aa_nonce(addr, 1235),
        'initCode':"0x",
        'callData': Web3.to_hex(calldata),
        'callGasLimit': "0x40000",
        'verificationGasLimit': "0x10000",
        'preVerificationGas': "0x10000",
        'maxFeePerGas': Web3.to_hex(0),
        'maxPriorityFeePerGas': Web3.to_hex(0),
        'paymasterAndData':"0x",
        'signature': '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c'
    }

    op = aa.sign_op(op, signer_key)

    # Because the bundler is not running yet we must call the EntryPoint directly.
    ho = EP.functions.handleOps([(
        op['sender'],
        Web3.to_int(hexstr=op['nonce']),
        op['initCode'],
        op['callData'],
        Web3.to_int(hexstr=op['callGasLimit']),
        Web3.to_int(hexstr=op['verificationGasLimit']),
        Web3.to_int(hexstr=op['preVerificationGas']),
        Web3.to_int(hexstr=op['maxFeePerGas']),
        Web3.to_int(hexstr=op['maxPriorityFeePerGas']),
        op['paymasterAndData'],
        op['signature'],
    )], deploy_addr).build_transaction({
        'from': deploy_addr,
        'value': 0,
    })
    ho['gas'] = int(w3.eth.estimate_gas(ho) * 1.2)

    return l2_util.sign_and_submit(ho, deploy_key)

def permit_caller(acct, caller):
    """Whitelist a contract to call a HybridAccount. Now implemented as
       a UserOperation rather than requiring the Owner to be an EOA."""
    if not acct.functions.PermittedCallers(caller).call():
        print(f"Permit caller {caller} on {acct.address}")

        calldata = selector("PermitCaller(address,bool)") + \
          ethabi.encode(['address','bool'], [caller, True])

        submit_as_op(acct.address, calldata, env_vars['OC_PRIVKEY'])

def register_url(caller, url):
    """Associates a URL with the address of a HybridAccount contract"""
    if HH.functions.RegisteredCallers(caller).call()[1] != url:
        print("Calling RegisterUrl()")
        tx = HH.functions.RegisterUrl(caller, url).build_transaction({
            'from': deploy_addr,
        })
        l2_util.sign_and_submit(tx, deploy_key)

    print("Credit balance =", HH.functions.RegisteredCallers(caller).call()[2])
    if HH.functions.RegisteredCallers(caller).call()[2] == 0:
        print("Calling AddCredit()")
        tx = HH.functions.AddCredit(caller, 100).build_transaction({
            'from': deploy_addr,
        })
        l2_util.sign_and_submit(tx, deploy_key)

def fund_addr(addr):
    """Transfer funds to an address directly"""
    if w3.eth.get_balance(addr) == 0:
        print("Funding acct (direct)", addr)
        tx = {
            'from': deploy_addr,
            'to': addr,
            'value': Web3.to_wei(1.001, 'ether')
        }
        if w3.eth.gas_price > 1000000:
            tx['gasPrice'] = w3.eth.gas_price
        else:
            tx['gasPrice'] = Web3.to_wei(1, 'gwei')
        l2_util.sign_and_submit(tx, deploy_key)

def fund_addr_ep(EP, addr):
    """Deposit funds for an address into the EntryPoint"""
    if EP.functions.deposits(addr).call()[0] < Web3.to_wei(0.005, 'ether'):
        print("Funding acct (depositTo)", addr)
        tx = EP.functions.depositTo(addr).build_transaction({
            'from': deploy_addr,
            'value': Web3.to_wei(0.01, "ether")
        })
        l2_util.sign_and_submit(tx, deploy_key)
    print("Balances for", addr, Web3.from_wei(w3.eth.get_balance(addr), 'ether'),
          Web3.from_wei(EP.functions.deposits(addr).call()[0], 'ether'))

def deploy_account(factory, owner):
    """Deploy an account using a Factory contract"""
    calldata = selector("createAccount(address,uint256)") + ethabi.encode(['address','uint256'],[owner,0])
    acct_addr_hex = Web3.to_hex(w3.eth.call({'to': factory, 'data':calldata}))
    acct_addr = Web3.to_checksum_address("0x" + str(acct_addr_hex)[26:])

    if len(w3.eth.get_code(acct_addr)) == 0:
        tx = {
            'to': factory,
            'data': calldata,
            'from': deploy_addr,
        }
        l2_util.sign_and_submit(tx, deploy_key)
    return acct_addr

def deploy_forge(script, cmd_env):
    args = ["/home/enya/.foundry/bin/forge", "script", "--silent", "--json", "--broadcast"]
    args.append("--rpc-url=http://127.0.0.1:9545")
    args.append("--contracts")
    args.append("src/hc0_6")
    args.append("--remappings")
    args.append("@openzeppelin/=lib/openzeppelin-contracts-versions/v4_9")
    args.append(script)
    sys_env = os.environ.copy()

    cmd_env['PATH'] = sys_env['PATH']
    cmd_env['PRIVATE_KEY'] = deploy_key
    cmd_env['DEPLOY_ADDR'] = deploy_addr
    cmd_env['DEPLOY_SALT'] = cli_args.deploy_salt  # Update to force redeployment
    cmd_env['ENTRY_POINTS'] = env_vars['ENTRY_POINTS']

    out = subprocess.run(args, cwd="../crates/types/contracts", env=cmd_env,
        capture_output=True, check=True)

    # Subprocess will fail if contracts were previously deployed but those addresses were
    # not passed in as env variables. Retry on a cleanly deployed devnet or change deploy_salt.
    if out.returncode != 0:
      print(out)
    assert out.returncode == 0

    jstr = out.stdout.split(b'\n')[0].decode('ascii')
    ret_json = json.loads(jstr)
    addrs_raw = ret_json['returns']['0']['value']
    # Need to parse the 'internal_type': 'address[5]' value
    addrs = addrs_raw[1:-1].replace(' ','')
    return addrs

def deploy_base():
    """Deploy the basic contracts needed for the local system"""
    cmd_env = {}
    cmd_env['HC_SYS_OWNER'] = env_vars['HC_SYS_OWNER']
    cmd_env['BOBA_TOKEN'] = boba_token
    addrs = deploy_forge("hc_scripts/LocalDeploy.s.sol", cmd_env)
    print("Deployed base contracts:", addrs)
    return addrs.split(',')

def deploy_examples(hybrid_acct_addr):
    cmd_env = {}
    cmd_env['OC_HYBRID_ACCOUNT'] = hybrid_acct_addr
    addrs = deploy_forge("hc_scripts/ExampleDeploy.s.sol", cmd_env)
    print("Deployed example contracts:", addrs)
    return addrs.split(',')

deployed = {}

def get_contract(cname, deployed_addr):
    """Creates a web3.py interface to a deployed contract"""
    c = w3.eth.contract(abi=contract_info[cname]['abi'], address=deployed_addr)
    deployed[cname] = {}
    deployed[cname]['abi'] = contract_info[cname]['abi']
    deployed[cname]['address'] = deployed_addr
    return c

def boba_balance(addr):
    """Returns the Boba token balance of an address"""
    bal_calldata = selector("balanceOf(address)") + ethabi.encode(['address'], [addr])
    bal = w3.eth.call({'to':boba_token, 'data':bal_calldata})
    return Web3.to_int(bal)

EP = load_contract(w3, "EntryPoint", "../crates/types/contracts/lib/account-abstraction-versions/v0_6/deployments/optimism/EntryPoint.json", "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")

assert l1.eth.get_balance(deploy_addr) > Web3.to_wei(1000, 'ether')

print("Deployer balance:", w3.eth.get_balance(deploy_addr))

FUND_MIN = 50

if w3.eth.get_balance(deploy_addr) < Web3.to_wei(FUND_MIN, 'ether'):
    tx = {
        'from': deploy_addr,
        'to': Web3.to_checksum_address(portal_addr),
        'value': Web3.to_wei(2 * FUND_MIN, 'ether')
    }
    print("Funding L2 deploy_addr (ETH)")
    l1_util.sign_and_submit(tx, deploy_key)

    print("Sleep...")
    while w3.eth.get_balance(deploy_addr) == 0:
        time.sleep(2)
    print("Continuing")


if boba_balance(deploy_addr) < Web3.to_wei(FUND_MIN, 'ether'):
    l1_util.approve_token(boba_l1_addr, bridge_addr, deploy_addr, deploy_key)

    depositCD = selector("depositERC20(address,address,uint256,uint32,bytes)") + ethabi.encode(
        ['address','address','uint256','uint32','bytes'], [
          boba_l1_addr,
          boba_token,
          Web3.to_wei(2 * FUND_MIN,'ether'),
          4000000,
          Web3.to_bytes(hexstr="0x")
        ])
    tx = {
        'from': deploy_addr,
        'data': Web3.to_hex(depositCD),
        'to': bridge_addr,
    }
    tx['gas'] = int(l1.eth.estimate_gas(tx) * 1.5)
    print("Funding L2 deploy_addr (BOBA)")
    l1_util.sign_and_submit(tx, deploy_key)

    print("Sleep...")
    while boba_balance(deploy_addr) == 0:
        time.sleep(2)
    print("Continuing")

fund_addr(env_vars['BUNDLER_ADDR'])

(ep_addr, hh_addr, saf_addr, haf_addr, ha0_addr) = deploy_base()

aa = aa_rpc(ep_addr, w3, None)

HH = load_contract(w3, 'HCHelper', OUT_PREFIX + "HCHelper.sol/HCHelper.json", hh_addr)
l2_util.approve_token(boba_token, HH.address, deploy_addr, deploy_key)

tx = HH.functions.SetPrice(Web3.to_wei(0.1,'ether')). build_transaction({
    'from': deploy_addr,
})
l2_util.sign_and_submit(tx, deploy_key)

client_addr = deploy_account(saf_addr, env_vars['CLIENT_OWNER'])
fund_addr(client_addr)

ha1_addr = deploy_account(haf_addr, env_vars['OC_OWNER'])
fund_addr_ep(EP, ha1_addr)

HA = load_contract(w3, 'HybridAccount', OUT_PREFIX + "HybridAccount.sol/HybridAccount.json", ha1_addr)
SA = load_contract(w3, 'SimpleAccount', OUT_PREFIX + "SimpleAccount.sol/SimpleAccount.json", client_addr)

example_addrs = deploy_examples(ha1_addr)

TEST_AUCTION = load_contract(w3, 'TestAuctionSystem', OUT_PREFIX + "TestAuctionSystem.sol/AuctionFactory.json", example_addrs[0])
CAPTCHA = load_contract(w3, 'TestCaptcha', OUT_PREFIX + "TestCaptcha.sol/TestCaptcha.json", example_addrs[1])
TC = load_contract(w3, 'TestHybrid', OUT_PREFIX + "TestHybrid.sol/TestHybrid.json", example_addrs[2])
RAINFALL_INSURANCE = load_contract(w3, 'TestRainfallInsurance', OUT_PREFIX + "TestRainfallInsurance.sol/RainfallInsurance.json", example_addrs[3])
TEST_SPORTS_BETTING = load_contract(w3, 'TestSportsBetting', OUT_PREFIX + "TestSportsBetting.sol/SportsBetting.json", example_addrs[4])
KYC = load_contract(w3, 'TestKyc', OUT_PREFIX + "TestKyc.sol/TestKyc.json", example_addrs[5])
TEST_TOKEN_PRICE = load_contract(w3, 'TestTokenPrice', OUT_PREFIX + "TestTokenPrice.sol/TestTokenPrice.json", example_addrs[6])

for a in example_addrs:
    permit_caller(HA, a)

LOCAL_URL = "http://" + str(local_ip) + ":1234/hc"
register_url(ha1_addr, LOCAL_URL)

with open("./contracts.json", "w", encoding="ascii") as f:
    f.write(json.dumps(deployed))

print("Writing .env file")
if os.path.exists(".env"):
    # .env.old is left as a backup
    os.rename(".env", ".env.old")

# Deployed addresses
env_vars['ENTRY_POINTS'] = EP.address
env_vars['HC_HELPER_ADDR'] = HH.address
env_vars['HC_SYS_ACCOUNT'] = ha0_addr
env_vars['OC_HYBRID_ACCOUNT'] = ha1_addr
env_vars['CLIENT_ADDR'] = client_addr
env_vars['SA_FACTORY_ADDR'] = saf_addr
env_vars['HA_FACTORY_ADDR'] = haf_addr

# Example contracts
env_vars['TEST_COUNTER'] = TC.address
env_vars['TEST_AUCTION'] = TEST_AUCTION.address
env_vars['TEST_RAINFALL_INSURANCE'] = RAINFALL_INSURANCE.address
env_vars['TEST_SPORTS_BETTING'] = TEST_SPORTS_BETTING.address
env_vars['TEST_KYC'] = KYC.address
env_vars['TEST_TOKEN_PRICE'] = TEST_TOKEN_PRICE.address

with open(".env", "w", encoding="ascii") as f:
    for k in env_vars.items():
        f.write(f"{k[0]}={k[1]}\n")
