import os
import sys
from web3 import Web3, exceptions
import requests,json
from web3.middleware import geth_poa_middleware
from jsonrpcclient import request, parse, Ok
from solcx import compile_source
import solcx
import time
import re
import subprocess
from eth_abi import abi as ethabi
import socket
import argparse
import eth_account

env_vars = dict()

parser = argparse.ArgumentParser()
parser.add_argument("--boba-path", required=True, help="Path to your local Boba/Optimism repository")
parser.add_argument("--deploy-salt", required=False, help="Salt value for contract deployment", default="0")

cli_args = parser.parse_args()

op_path = "/home/enya/v3-boba/optimism"
with open(cli_args.boba_path + "/.devnet/addresses.json","r") as f:
  jj = json.load(f)
  boba_l1_addr = Web3.to_checksum_address(jj['BOBA'])
  bridge_addr  = Web3.to_checksum_address(jj['L1StandardBridgeProxy'])
  portal_addr  = Web3.to_checksum_address(jj['OptimismPortalProxy'])

with open(cli_args.boba_path + "/op-service/predeploys/addresses.go","r") as f:
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
with open("local.env","r") as f:
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
assert (l1.is_connected)
l1.middleware_onion.inject(geth_poa_middleware, layer=0)

w3 = Web3(Web3.HTTPProvider(env_vars['NODE_HTTP']))
assert (w3.is_connected)

HC_CHAIN = int(env_vars['CHAIN_ID'])

solcx.install_solc("0.8.17")
solcx.set_solc_version("0.8.17")
contract_info = dict()
path_prefix = "../crates/types/contracts/lib/account-abstraction/contracts/"

def loadContract(w3, name, files):
  compiled = solcx.compile_files(
    files,
    output_values=['abi', 'bin', 'bin-runtime'],
    import_remappings={
        "@openzeppelin": "../crates/types/contracts/lib/openzeppelin-contracts"},
    allow_paths=[path_prefix],
    optimize=True,
    optimize_runs=1000000,
  )

  for k in compiled.keys():
    if re.search(re.compile(name), k):
      break
  contract_info[name] = dict()

  contract_info[name]['abi'] = compiled[k]['abi']
  contract_info[name]['bin'] = compiled[k]['bin']
  return w3.eth.contract(abi=contract_info[name]['abi'], bytecode=contract_info[name]['bin'])

def signAndSubmit(w, tx, key):
  signed_txn = w.eth.account.sign_transaction(tx, key)
  ret = w.eth.send_raw_transaction(signed_txn.rawTransaction)
  rcpt = w.eth.wait_for_transaction_receipt(ret)
  if (rcpt.status != 1):
    print("Transaction failed, txhash =", Web3.to_hex(ret))
  assert (rcpt.status == 1)
  return rcpt

def aa_nonce(addr):
  calldata = selector("getNonce(address,uint192)") + ethabi.encode(['address','uint192'],[addr, 1235])
  ret = w3.eth.call({'to':EP.address,'data':calldata})
  return Web3.to_hex(ret)

# Wrapper to build and submit a UserOperation directly to the EntryPoint. We don't
# have a Bundler to run gas estimation so the values are hard-coded. It might be
# necessary to change these values e.g. if simulating different L1 prices on the local devnet

def submitAsOp(addr, calldata, signer_key):
  op = {
      'sender':addr,
      'nonce': aa_nonce(addr),
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

  pack1 = ethabi.encode(['address','uint256','bytes32','bytes32','uint256','uint256','uint256','uint256','uint256','bytes32'], \
    [op['sender'],
    Web3.to_int(hexstr=op['nonce']),
    Web3.keccak(hexstr=op['initCode']),
    Web3.keccak(hexstr=op['callData']),
    Web3.to_int(hexstr=op['callGasLimit']),
    Web3.to_int(hexstr=op['verificationGasLimit']),
    Web3.to_int(hexstr=op['preVerificationGas']),
    Web3.to_int(hexstr=op['maxFeePerGas']),
    Web3.to_int(hexstr=op['maxPriorityFeePerGas']),
    Web3.keccak(hexstr=op['paymasterAndData']),
    ])

  pack2 = ethabi.encode(['bytes32','address','uint256'], [Web3.keccak(pack1), EP.address, w3.eth.chain_id])
  eMsg = eth_account.messages.encode_defunct(Web3.keccak(pack2))
  sig = w3.eth.account.sign_message(eMsg, private_key=signer_key)
  op['signature'] = Web3.to_hex(sig.signature)

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
    'nonce': w3.eth.get_transaction_count(deploy_addr),
  })
  ho['gas'] = int(w3.eth.estimate_gas(ho) * 1.2)

  return signAndSubmit(w3, ho, deploy_key)

# Whitelist a contract to call a HybridAccount. Now implemented as
# a UserOperation rather than requiring the Owner to be an EOA.
def permitCaller(acct, caller):
    if not acct.functions.PermittedCallers(caller).call():
        print("Permit caller {} on {}".format(caller, acct.address))

        calldata = selector("PermitCaller(address,bool)") + \
          ethabi.encode(['address','bool'], [caller, True])

        submitAsOp(acct.address, calldata, env_vars['OC_PRIVKEY'])

# FIXME - this should be moved out of deploy-local and into the code which
# runs the associcated test cases.
def buy_insurance(contract):
    trigger_rainfall = 50
    city = "London"
    premium = w3.to_wei(0.0001, 'ether')

    calldata = selector("buyInsurance(uint256,string)") + \
      ethabi.encode(['uint256','string'],[trigger_rainfall, city])

    exCall = selector("execute(address,uint256,bytes)") + \
      ethabi.encode(['address', 'uint256', 'bytes'], [contract.address, premium, Web3.to_bytes(calldata)])

    rcpt = submitAsOp(client_addr, exCall, env_vars['CLIENT_PRIVKEY'])
    logs = rcpt['logs']
    policy_id = 0
    for i in range(len(logs)):
      if logs[i].address == contract.address:
        policy_id = Web3.to_hex(logs[i].topics[1])

    # For compatibility, would probably be cleaner to represent the policy id as hex
    print("buy_insurance policy id = ", policy_id)
    return Web3.to_int(hexstr=policy_id)

def registerUrl(caller, url):
    print("Credit balance=", HH.functions.RegisteredCallers(caller).call()[2])
    # Temporary hack
    if HH.functions.RegisteredCallers(caller).call()[1] != url or HH.functions.RegisteredCallers(caller).call()[2] == 0:
        print("Calling RegisterUrl()")
        tx = HH.functions.RegisterUrl(caller, url).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })

        signAndSubmit(w3, tx, deploy_key)
        print("Calling AddCredit()")
        tx = HH.functions.AddCredit(caller, 100).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(w3, tx, deploy_key)

def fundAddr(addr):
    if w3.eth.get_balance(addr) == 0:
        print("Funding acct (direct)", addr)
        n = w3.eth.get_transaction_count(deploy_addr)
        v = Web3.to_wei(1.001, 'ether')
        # v += Web3.to_wei(n, 'wei')
        tx = {
            'nonce': n,
            'from': deploy_addr,
            'to': addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
            'value': v
        }
        if w3.eth.gas_price > 1000000:
            tx['gasPrice'] = w3.eth.gas_price
        else:
            tx['gasPrice'] = Web3.to_wei(1, 'gwei')
        signAndSubmit(w3, tx, deploy_key)

def fundAddrEP(EP, addr):
    if EP.functions.deposits(addr).call()[0] < Web3.to_wei(0.005, 'ether'):
        print("Funding acct (depositTo)", addr)
        tx = EP.functions.depositTo(addr).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
            'value': Web3.to_wei(0.01, "ether")
        })
        signAndSubmit(w3, tx, deploy_key)
    print("Balances for", addr, Web3.from_wei(w3.eth.get_balance(addr), 'ether'),
          Web3.from_wei(EP.functions.deposits(addr).call()[0], 'ether'))

def selector(name):
    nameHash = Web3.to_hex(Web3.keccak(text=name))
    return Web3.to_bytes(hexstr=nameHash[:10])

def deployAccount(factory, owner):
  calldata = selector("createAccount(address,uint256)") + ethabi.encode(['address','uint256'],[owner,0])
  acct_addr_hex = Web3.to_hex(w3.eth.call({'to': factory, 'data':calldata}))
  acct_addr = Web3.to_checksum_address("0x" + acct_addr_hex[26:])

  if len(w3.eth.get_code(acct_addr)) == 0:
    tx = {
        'to': factory,
        'data': calldata,
        'nonce': w3.eth.get_transaction_count(deploy_addr),
        'from': deploy_addr,
        'gas': 210000,
        'gasPrice': w3.eth.gas_price,
        'chainId': HC_CHAIN,
    }
    rcpt = signAndSubmit(w3, tx, deploy_key)
    assert(rcpt.status == 1)

  return acct_addr

# Deploy the basic contracts needed for the local system
def deployBase():
  args = ["forge", "script", "--json", "--broadcast", "--silent"]
  args.append ("--rpc-url=http://127.0.0.1:9545")
  args.append("hc_scripts/LocalDeploy.s.sol")
  cmd_env = os.environ.copy()
  cmd_env['PRIVATE_KEY'] = deploy_key
  cmd_env['HC_SYS_OWNER'] = env_vars['HC_SYS_OWNER']
  cmd_env['DEPLOY_ADDR'] = deploy_addr
  cmd_env['DEPLOY_SALT'] = cli_args.deploy_salt  # Update to force redeployment
  cmd_env['BOBA_TOKEN'] = boba_token

  out = subprocess.run(args, cwd="../crates/types/contracts", env=cmd_env, capture_output=True)

  # Subprocess will fail if contracts were previously deployed but those addresses were
  # not passed in as env variables. Retry on a cleanly deployed devnet or change salt_val in the contract.
  assert(out.returncode == 0)

  jstr = out.stdout.split(b'\n')[0].decode('ascii')
  ret_json = json.loads(jstr)
  addrs_raw = ret_json['returns']['0']['value']
  # Need to parse the 'internal_type': 'address[5]' value
  addrs = addrs_raw[1:-1].replace(' ','')
  print("Deployed base contracts", addrs)
  return addrs.split(',')


def deployExamples(ha1_addr):
  args = ["forge", "script", "--json", "--broadcast", "--silent"]
  args.append ("--rpc-url=http://127.0.0.1:9545")
  args.append("hc_scripts/ExampleDeploy.s.sol")
  cmd_env = os.environ.copy()
  cmd_env['PRIVATE_KEY'] = deploy_key
  cmd_env['OC_HYBRID_ACCOUNT'] = ha1_addr

  out = subprocess.run(args, cwd="../crates/types/contracts", env=cmd_env, capture_output=True)
  assert(out.returncode == 0)
  jstr = out.stdout.split(b'\n')[0].decode('ascii')
  ret_json = json.loads(jstr)
  addrs_raw = ret_json['returns']['0']['value']
  addrs = addrs_raw[1:-1].replace(' ','')
  print("Deployed example contracts")
  return addrs.split(',')

deployed = dict()

def getContract(cname, deployed_addr):
  C = w3.eth.contract(abi=contract_info[cname]['abi'], address=deployed_addr)
  deployed[cname] = dict()
  deployed[cname]['abi'] = contract_info[cname]['abi']
  deployed[cname]['address'] = deployed_addr
  return C

def approveToken(rpc, token, spender):
  approveCD = selector("approve(address,uint256)") + ethabi.encode(
    ['address','uint256'],
    [spender, Web3.to_int(hexstr="0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")])

  tx = {
      'nonce': rpc.eth.get_transaction_count(deploy_addr),
      'from': deploy_addr,
      'data': approveCD,
      'to': token,
      'gas': 210000,
      'gasPrice': rpc.eth.gas_price,
      'chainId': rpc.eth.chain_id,
  }
  print("Boba ERC20 approval")
  signAndSubmit(rpc, tx, deploy_key)

def bobaBalance(addr):
  balCD = selector("balanceOf(address)") + ethabi.encode(['address'], [addr]);
  bal = w3.eth.call({'to':boba_token, 'data':balCD})
  return bal

HH = loadContract(w3, "HCHelper",      path_prefix+"core/HCHelper.sol")
KYC = loadContract(w3, "TestKyc",          path_prefix+"test/TestKyc.sol")
TestTokenPrice = loadContract(
    w3, "TestTokenPrice", path_prefix+"test/TestTokenPrice.sol")
TestCaptcha = loadContract(
    w3, "TestCaptcha", path_prefix+"test/TestCaptcha.sol")
TC = loadContract(w3, "TestCounter",   path_prefix+"test/TestCounter.sol")
TestRainfallInsurance = loadContract(
    w3, "TestRainfallInsurance", path_prefix+"test/TestRainfallInsurance.sol")
EP = loadContract(w3, "EntryPoint",    path_prefix+"core/EntryPoint.sol")
SA = loadContract(w3, "SimpleAccount", path_prefix+"samples/SimpleAccount.sol")
HA = loadContract(w3, "HybridAccount", path_prefix+"samples/HybridAccount.sol")
TEST_AUCTION = loadContract(w3, "TestAuctionSystem", path_prefix+"test/TestAuctionSystem.sol")
SPORT_BET = loadContract(w3, "TestSportsBetting", path_prefix+"test/TestSportsBetting.sol")

assert (l1.eth.get_balance(deploy_addr) > Web3.to_wei(1000, 'ether'))

print('balance', w3.eth.get_balance(deploy_addr))

if w3.eth.get_balance(deploy_addr) == 0:
  tx = {
      'nonce': l1.eth.get_transaction_count(deploy_addr),
      'from': deploy_addr,
      # Portal
      'to': Web3.to_checksum_address(portal_addr),
      'gas': 210000,
      'gasPrice': l1.eth.gas_price,
      'chainId': 900,
      'value': Web3.to_wei(1000, 'ether')
  }
  print("Funding L2 deploy_addr (ETH)")
  signAndSubmit(l1, tx, deploy_key)

  print("Sleep...")
  while w3.eth.get_balance(deploy_addr) == 0:
    time.sleep(2)
  print("Continuing")


if bobaBalance(deploy_addr) == 0 or True:
  approveToken(l1, boba_l1_addr, bridge_addr)

  depositCD = selector("depositERC20(address,address,uint256,uint32,bytes)") + ethabi.encode(
    ['address','address','uint256','uint32','bytes'],
    [boba_l1_addr, boba_token, Web3.to_wei(100,'ether'), 4000000, Web3.to_bytes(hexstr="0x")])
  tx = {
      'nonce': l1.eth.get_transaction_count(deploy_addr),
      'from': deploy_addr,
      'data': Web3.to_hex(depositCD),
      'to': bridge_addr,
      'chainId': 900,
  }
  tx['gas'] = int(l1.eth.estimate_gas(tx) * 1.5)
  tx['gasPrice'] = l1.eth.gas_price
  print("Funding L2 deploy_addr (BOBA)")
  signAndSubmit(l1, tx, deploy_key)

  print("Sleep...")
  while bobaBalance(deploy_addr) == 0:
    time.sleep(2)
  print("Continuing")

deployed = dict()

fundAddr(env_vars['BUNDLER_ADDR'])
#fundAddr(client_owner)
(ep_addr, hh_addr, saf_addr, haf_addr, ha0_addr) = deployBase()

EP = getContract('EntryPoint',ep_addr)
HH = getContract('HCHelper',hh_addr)

approveToken(w3, boba_token, HH.address)

tx = HH.functions.SetPrice(Web3.to_wei(0.1,'ether')). build_transaction({
    'nonce': w3.eth.get_transaction_count(deploy_addr),
    'from': deploy_addr,
    'gas': 210000,
    'chainId': HC_CHAIN,
})
signAndSubmit(w3, tx, deploy_key)

client_addr = deployAccount(saf_addr, env_vars['CLIENT_OWNER'])
fundAddr(client_addr)

ha1_addr = deployAccount(haf_addr, env_vars['OC_OWNER'])
fundAddrEP(EP, ha1_addr)
HA = getContract('HybridAccount',ha1_addr)
SA = getContract('SimpleAccount', client_addr)

example_addrs = deployExamples(ha1_addr)

TEST_AUCTION = getContract('TestAuctionSystem', example_addrs[0])
CAPTCHA = getContract('TestCaptcha', example_addrs[1])
TC = getContract('TestCounter', example_addrs[2])
RAINFALL_INSURANCE = getContract('TestRainfallInsurance', example_addrs[3])
TEST_SPORTS_BETTING = getContract('TestSportsBetting', example_addrs[4])

for a in example_addrs:
  permitCaller(HA, a)

policy_id = buy_insurance(RAINFALL_INSURANCE) # Broken
local_url = "http://" + str(local_ip) + ":1234/hc"
registerUrl(ha1_addr, local_url)

with open("./contracts.json", "w") as f:
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
env_vars['POLICY_ID'] = policy_id
env_vars['TEST_COUNTER'] = TC.address
env_vars['TEST_AUCTION'] = TEST_AUCTION.address
env_vars['TEST_RAINFALL_INSURANCE'] = RAINFALL_INSURANCE.address
env_vars['TEST_SPORTS_BETTING'] = TEST_SPORTS_BETTING.address

with open(".env","w") as f:
  for k in env_vars:
    f.write("{}={}\n".format(k,env_vars[k]))
