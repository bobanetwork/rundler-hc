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

if w3.eth.get_balance(factory_owner) == 0:
  print("Funding factory_owner")
  tx = {
      'nonce': w3.eth.get_transaction_count(deploy_addr),
      'from':deploy_addr,
      'to':factory_owner,
      'gas':210000,
      'gasPrice': w3.eth.gas_price,
      'chainId': HC_CHAIN,
      'value': Web3.to_wei(10,'ether')
  }
  signAndSubmit(w3, tx, deploy_key)

  print("Sleep...")
  while w3.eth.get_balance(factory_owner) == 0:
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
  return c2_addr

epAddr  = deploy2("EntryPoint", EP.constructor(),0)
hhAddr  = deploy2("HCHelper", HH.constructor(epAddr, boba_addr, 0),0)
saAddr  = deploy2("SimpleAccount", SA.constructor(epAddr),0)
ha0Addr = deploy2("HybridAccount.0", HA.constructor(epAddr, hhAddr),0)
ha1Addr = deploy2("HybridAccount.1", HA.constructor(epAddr, hhAddr),1)
tcAddr  = deploy2("TestCounter", TC.constructor(ha1Addr),0)

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
  env_vars['ENTRY_POINTS'] = epAddr
  env_vars['HC_HELPER_ADDR'] = hhAddr
  env_vars['HC_SYS_ACCOUNT'] = ha0Addr
  env_vars['OC_HYBRID_ACCOUNT'] = ha1Addr
  with open(".env","w") as f:
    for k in env_vars:
      f.write("{}={}\n".format(k,env_vars[k]))
  # .env.old is left as a backup
