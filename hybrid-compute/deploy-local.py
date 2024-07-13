import os
import sys
from web3 import Web3, exceptions
import requests
import json
from web3.middleware import geth_poa_middleware

from solcx import compile_source
import solcx
import time
import re
import subprocess
from eth_abi import abi as ethabi

boba_addr = Web3.to_checksum_address(
    "0x4200000000000000000000000000000000000023")

# The following addrs and keys are for local demo purposes. Do not deploy to public networks

deploy_addr = Web3.to_checksum_address(
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
deploy_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

bundler_addr = Web3.to_checksum_address(
    "0xB834a876b7234eb5A45C0D5e693566e8842400bB")
builder_privkey = "0xf91be07ef5a01328015cae4f2e5aefe3c4577a90abb8e2e913fe071b0e3732ed"

client_owner = Web3.to_checksum_address("0x77Fe14A710E33De68855b0eA93Ed8128025328a9")
client_privkey = "0x541b3e3b20b8bb0e5bae310b2d4db4c8b7912ba09750e6ff161b7e67a26a9bf7"

ha0_owner = Web3.to_checksum_address("0x2A9099A58E0830A4Ab418c2a19710022466F1ce7")
ha0_privkey = "0x75cd983f0f4714969b152baa258d849473732905e2301467303dacf5a09fdd57"

# HC1 is used by the offchain JSON-RPC endpoint
ha1_owner = Web3.to_checksum_address(
    "0xE073fC0ff8122389F6e693DD94CcDc5AF637448e")
ha1_privkey = "0x7c0c629efc797f8c5f658919b7efbae01275470d59d03fdeb0fca1e6bd11d7fa"

l1 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert (l1.is_connected)
l1.middleware_onion.inject(geth_poa_middleware, layer=0)

l2 = Web3(Web3.HTTPProvider("http://127.0.0.1:9545"))
assert (l2.is_connected)
l2.middleware_onion.inject(geth_poa_middleware, layer=0)

w3 = l2
HC_CHAIN = 901

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
  assert (rcpt.status == 1)
  return rcpt
def permitCaller(acct, caller):
    if not acct.functions.PermittedCallers(caller).call():
        print("Permit caller {} on {}".format(caller, acct.address))
        tx = acct.functions.PermitCaller(caller, True).build_transaction({
            'nonce': w3.eth.get_transaction_count(ha1_owner),
            'from': ha1_owner,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(w3, tx, ha1_privkey)

def buy_insurance(contract):
    trigger_rainfall = 50
    city = "London"
    premium = w3.to_wei(0.01, 'ether')

    transaction = contract.functions.buyInsurance(
        trigger_rainfall,
        city
    ).build_transaction({
        'from': ha1_owner,
        'value': premium,
        'gas': 210000,
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': w3.eth.get_transaction_count(ha1_owner),
    })
    receipt = signAndSubmit(w3, transaction, ha1_privkey)

    policy_created_event = RAINFALL_INSURANCE.events.PolicyCreated().process_receipt(receipt)
    policy_id = policy_created_event[0]['args']['policyId']
    print("Policy ID: ", policy_id)

    return policy_id

def registerUrl(caller, url):
    print("Credit balance=", HH.functions.RegisteredCallers(caller).call()[2])
    # Temporray hack
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
  cmd_env['HC_SYS_OWNER'] = ha0_owner
  cmd_env['DEPLOY_SALT'] = "2"  # Update to force redeployment

  out = subprocess.run(args, cwd="../crates/types/contracts", env=cmd_env, capture_output=True)

  # Subprocess will fail if contracts were previously deployed but those addresses were
  # not passed in as env variables. Retry on a cleanly deployed devnet or change salt_val in the contract.
  assert(out.returncode == 0)

  jstr = out.stdout.split(b'\n')[0].decode('ascii')
  ret_json = json.loads(jstr)
  addrs_raw = ret_json['returns']['0']['value']
  # Need to parse the 'internal_type': 'address[5]' value
  addrs = addrs_raw[1:-1].replace(' ','')
  print("Deployed base contracts")
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
      'to': Web3.to_checksum_address("0x0165878a594ca255338adfa4d48449f69242eb8f"),
      'gas': 210000,
      'gasPrice': l1.eth.gas_price,
      'chainId': 900,
      'value': Web3.to_wei(1000, 'ether')
  }
  print("Funding L2 deploy_addr")
  signAndSubmit(l1, tx, deploy_key)

  print("Sleep...")
  while l2.eth.get_balance(deploy_addr) == 0:
    time.sleep(2)
  print("Continuing")

deployed = dict()

fundAddr(bundler_addr)
#fundAddr(client_owner)
(ep_addr, hh_addr, saf_addr, haf_addr, ha0_addr) = deployBase()

EP = getContract('EntryPoint',ep_addr)
HH = getContract('HCHelper',hh_addr)

# FIXME - fix permitCaller() so that these don't need to be funded, only to sign.
fundAddr(ha1_owner)

client_addr = deployAccount(saf_addr, client_owner)
fundAddr(client_addr)

ha1_addr = deployAccount(haf_addr, ha1_owner)
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

policy_id = buy_insurance(RAINFALL_INSURANCE)
# Change IP address as needed.
#registerUrl(HA.address, "http://192.168.178.37:1234/hc")
registerUrl(ha1_addr, "http://192.168.4.2:1234/hc")

with open("./contracts.json", "w") as f:
  f.write(json.dumps(deployed))

if os.path.exists(".env"):
  print("\nUpdating .env file")
  env_vars = dict()
  os.rename(".env", ".env.old")
  with open(".env.old","r") as f:
    for line in f.readlines():
      k,v = line.strip().split('=')
      env_vars[k] = v

  # Pre-generated accounts for local devnet.
  env_vars['BUNDLER_ADDR'] = bundler_addr
  env_vars['BUILDER_PRIVKEY'] = builder_privkey
  env_vars['HC_SYS_OWNER'] = ha0_owner
  env_vars['HC_SYS_PRIVKEY'] = ha0_privkey
  env_vars['OC_OWNER'] = ha1_owner
  env_vars['OC_PRIVKEY'] = ha1_privkey
  env_vars['CLIENT_OWNER'] = client_owner
  env_vars['CLIENT_PRIVKEY'] = client_privkey
  
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

  with open(".env","w") as f:
    for k in env_vars:
      f.write("{}={}\n".format(k,env_vars[k]))
  # .env.old is left as a backup
