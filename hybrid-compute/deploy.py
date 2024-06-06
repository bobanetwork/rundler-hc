import os,sys
from web3 import Web3, exceptions
import requests,json
from web3.middleware import geth_poa_middleware

from solcx import compile_source
import solcx
import time
import re

boba_addr = Web3.to_checksum_address("0x4200000000000000000000000000000000000023")

deploy_addr = Web3.to_checksum_address("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
deploy_key  = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

bundler_addr = Web3.to_checksum_address(
    "0xB834a876b7234eb5A45C0D5e693566e8842400bB")

# The following addrs and keys are for local demo purposes. Do not deploy to public networks
u_addr = Web3.to_checksum_address("0x77Fe14A710E33De68855b0eA93Ed8128025328a9")
u_key = "0x541b3e3b20b8bb0e5bae310b2d4db4c8b7912ba09750e6ff161b7e67a26a9bf7"

# HC1 is used by the offchain JSON-RPC endpoint
hc1_addr = Web3.to_checksum_address(
    "0xE073fC0ff8122389F6e693DD94CcDc5AF637448e")
hc1_key = "0x7c0c629efc797f8c5f658919b7efbae01275470d59d03fdeb0fca1e6bd11d7fa"

l1 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert (l1.is_connected)
l1.middleware_onion.inject(geth_poa_middleware, layer=0)

l2 = Web3(Web3.HTTPProvider("http://127.0.0.1:9545"))
assert (l2.is_connected)
l2.middleware_onion.inject(geth_poa_middleware, layer=0)

w3 = l2
HC_CHAIN=901
factory_addr = Web3.to_checksum_address("0x4e59b44847b379578588920ca78fbf26c0b4956c") # Deterministic deployer
factory_owner = Web3.to_checksum_address("0x3fab184622dc19b6109349b94811493bf2a45362")

solcx.install_solc("0.8.17")
solcx.set_solc_version("0.8.17")
contract_info=dict()
path_prefix="../crates/types/contracts/lib/account-abstraction/contracts/"

def loadContract(w3, name, files):
  compiled = solcx.compile_files(
    files,
    output_values=['abi', 'bin','bin-runtime'],
    import_remappings={"@openzeppelin":"../crates/types/contracts/lib/openzeppelin-contracts"},
    allow_paths=[path_prefix],
    optimize=True,
    optimize_runs=1000000,
  )

  for k in compiled.keys():
    if re.search(re.compile(name),k):
      break
  contract_info[name]=dict()

  contract_info[name]['abi'] = compiled[k]['abi']
  contract_info[name]['bin'] = compiled[k]['bin']
  return w3.eth.contract(abi=contract_info[name]['abi'], bytecode=contract_info[name]['bin'])

assert(l1.eth.get_balance(deploy_addr) > Web3.to_wei(1000,'ether'))

def signAndSubmit(w, tx, key):
  signed_txn =w.eth.account.sign_transaction(tx, key)
  ret = w.eth.send_raw_transaction(signed_txn.rawTransaction)
  rcpt = w.eth.wait_for_transaction_receipt(ret)
  assert(rcpt.status == 1)
  return rcpt

def buildAndSubmit(f, addr, key):
  tx = f.build_transaction({
       'nonce': l1.eth.get_transaction_count(addr),
      'from':addr,
      'gas':210000,
      'chainId': 900,
  })
  return signAndSubmit(tx, key)

HH = loadContract(w3, "HCHelper",      path_prefix+"core/HCHelper.sol")
KYC = loadContract(w3, "TestKyc",          path_prefix+"test/TestKyc.sol")
TestTokenPrice = loadContract(w3, "TestTokenPrice", path_prefix+"test/TestTokenPrice.sol")
TestCaptcha = loadContract(w3, "TestCaptcha", path_prefix+"test/TestCaptcha.sol")
TC = loadContract(w3, "TestCounter",   path_prefix+"test/TestCounter.sol")
EP = loadContract(w3, "EntryPoint",    path_prefix+"core/EntryPoint.sol")
SA = loadContract(w3, "SimpleAccount", path_prefix+"samples/SimpleAccount.sol")
HA = loadContract(w3, "HybridAccount", path_prefix+"samples/HybridAccount.sol")

if w3.eth.get_balance(deploy_addr) == 0:
  tx = {
      'nonce': l1.eth.get_transaction_count(deploy_addr),
      'from':deploy_addr,
      'to':Web3.to_checksum_address("0x0165878a594ca255338adfa4d48449f69242eb8f"), # Portal
      'gas':210000,
      'gasPrice': l1.eth.gas_price,
      'chainId': 900,
      'value': Web3.to_wei(1000,'ether')
  }
  print("Funding L2 deploy_addr")
  signAndSubmit(l1, tx, deploy_key)

  print("Sleep...")
  while l2.eth.get_balance(deploy_addr) == 0:
    time.sleep(2)
  print("Continuing")

deployed = dict()

def deploy2(name, cc, salt):
  initcode = cc.build_transaction()['data']
  salt32 = "{0:#066x}".format(salt)
  preimage = "0xff" + factory_addr[2:] + salt32[2:] + Web3.to_hex(Web3.keccak(hexstr=initcode))[2:]
  addrhash = Web3.to_hex(Web3.keccak(hexstr=preimage))
  c2_addr = Web3.to_checksum_address(addrhash[26:])
  if len(w3.eth.get_code(c2_addr)) > 0:
    print(name, "Already deployed at", c2_addr)
  else:
    tx = {
       'nonce': w3.eth.get_transaction_count(deploy_addr),
       'to':factory_addr,
       'from':deploy_addr,
       'gas':9900000,
       'gasPrice': w3.eth.gas_price,
       'chainId': HC_CHAIN,
       'data': salt32 + initcode[2:]
       }
    tx['gas'] = w3.eth.estimate_gas(tx)
    rcpt = signAndSubmit(w3, tx, deploy_key)

    print(name, "deployed to", c2_addr)
  cname = name
  if re.match(r'HybridAccount',cname):
    cname = "HybridAccount"

  assert(len(w3.eth.get_code(c2_addr)) > 0)

  deployed[name] = dict()
  deployed[name]['abi'] = contract_info[cname]['abi']
  deployed[name]['address'] = c2_addr

  C = w3.eth.contract(abi=contract_info[cname]['abi'], address=c2_addr)
  return C

def setOwner(acct, owner):
    if acct.functions.owner().call() != owner:
        print("Setting owner")
        tx = acct.functions.initialize(owner).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(w3, tx, deploy_key)

def setSysAcct(HH, sys):
    if HH.functions.systemAccount().call() != sys:
        print("Setting systemAccount")
        tx = HH.functions.SetSystemAccount(sys).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(w3, tx, deploy_key)

def permitCaller(acct, caller):
    if not acct.functions.PermittedCallers(caller).call():
        print("Permit caller {} on {}".format(caller, acct.address))
        tx = acct.functions.PermitCaller(caller, True).build_transaction({
            'nonce': w3.eth.get_transaction_count(hc1_addr),
            'from': hc1_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(w3, tx, hc1_key)

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

fundAddr(bundler_addr)
fundAddr(u_addr)
# FIXME - fix permitCaller() so that these don't need to be funded, only to sign.
fundAddr(hc1_addr)

EP  = deploy2("EntryPoint", EP.constructor(),0)
HH  = deploy2("HCHelper", HH.constructor(EP.address, boba_addr, 0),0)
setOwner(HH, deploy_addr)

SA  = deploy2("SimpleAccount", SA.constructor(EP.address),0)
setOwner(SA, u_addr)
fundAddr(SA.address)

BA = deploy2("HybridAccount.0", HA.constructor(EP.address, HH.address),0)
setSysAcct(HH, BA.address)
setOwner(BA, Web3.to_checksum_address("0x2A9099A58E0830A4Ab418c2a19710022466F1ce7"))
fundAddrEP(EP, BA.address)

HA = deploy2("HybridAccount.1", HA.constructor(EP.address, HH.address),1)
setOwner(HA, hc1_addr)
fundAddrEP(EP, HA.address)

TC  = deploy2("TestCounter", TC.constructor(HA.address),0)
KYC = deploy2("TestKyc", KYC.constructor(HA.address), 0 )
TFP = deploy2("TestTokenPrice", TestTokenPrice.constructor(HA.address), 0)
CAPTCHA = deploy2("TestCaptcha", TestCaptcha.constructor(HA.address), 0)

# Change IP address as needed.
registerUrl(HA.address, "http://192.168.178.59:1234/hc")
#registerUrl(HA.address, "http://192.168.4.2:1234/hc")

permitCaller(HA, TC.address)
permitCaller(HA, KYC.address)
permitCaller(HA, TFP.address)
permitCaller(HA, CAPTCHA.address)

with open("./contracts.json", "w") as f:
  f.write(json.dumps(deployed))
with open("addresses.txt", "w") as f:
  for c in deployed:
    f.write(c + "\t" + deployed[c]['address']+"\n")

if os.path.exists(".env"):
  print("\nUpdating .env file")
  env_vars = dict()
  os.rename(".env", ".env.old")
  with open(".env.old","r") as f:
    for line in f.readlines():
      k,v = line.strip().split('=')
      env_vars[k] = v
  env_vars['ENTRY_POINTS'] = EP.address
  env_vars['HC_HELPER_ADDR'] = HH.address
  env_vars['HC_SYS_ACCOUNT'] = BA.address
  env_vars['OC_HYBRID_ACCOUNT'] = HA.address
  env_vars['CLIENT_ADDR'] = SA.address
  env_vars['CLIENT_OWNER'] = u_addr
  env_vars['CLIENT_PRIVKEY'] = u_key
  with open(".env","w") as f:
    for k in env_vars:
      f.write("{}={}\n".format(k,env_vars[k]))
  # .env.old is left as a backup
