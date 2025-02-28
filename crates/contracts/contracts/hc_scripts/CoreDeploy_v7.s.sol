// SPDX-License-Identifier: UNLICENSED
// forge script --json --broadcast --via-ir --rpc-url <url> --contracts src/hc0_7 \
//   --remappings @openzeppelin/=lib/openzeppelin-contracts-versions/v5_0
//   --verifier-url <vfy> \
//   hc_scripts/CoreDeploy_v7.sol

pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "lib/account-abstraction-versions/v0_7/contracts/core/EntryPoint.sol";
import "src/hc0_7/HCHelper.sol";
import "src/hc0_7/HybridAccountFactory.sol";

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract CoreDeploy is Script {
    function run() external
        returns (address[4] memory) {
        address deployAddr = vm.envAddress("DEPLOY_ADDR");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address hcSysOwner = vm.envAddress("HC_SYS_OWNER");
        uint256 deploySalt = vm.envUint("DEPLOY_SALT");

        EntryPoint ept;
        HCHelper helper;
        HybridAccountFactory haf;
        HybridAccount ha0;

        bytes32 salt_val = bytes32(deploySalt);
        uint112 min_deposit = 0.001 ether;

        vm.startBroadcast(deployerPrivateKey);

        // EntryPointAddr is hard-coded for the v0.7 implementation
        ept = EntryPoint(payable(0x0000000071727De22E5E9d8BAf0edAc6f37da032));

        HCHelper helperImpl = new HCHelper{salt: salt_val}(address(ept));

        TransparentUpgradeableProxy hProxy = new TransparentUpgradeableProxy{salt: salt_val}(
          address(helperImpl),
          hcSysOwner,
          abi.encodeCall(HCHelper.initialize, (deployAddr))
        );
        helper = HCHelper(address(hProxy));

        {
            address hafAddr = vm.envOr("HA_FACTORY_ADDR", 0x0000000000000000000000000000000000000000);
            if (hafAddr != address(0) && hafAddr.code.length > 0) {
                haf = HybridAccountFactory(hafAddr);
            } else {
                haf = new HybridAccountFactory{salt: salt_val}(ept, address(helper));
            }
        }
        {
            address ha0Addr = vm.envOr("HC_SYS_ACCOUNT", 0x0000000000000000000000000000000000000000);
            if (ha0Addr != address(0) && ha0Addr.code.length > 0) {
                ha0 = HybridAccount(payable(ha0Addr));
            } else {
                ha0 = haf.createAccount(hcSysOwner,0);
            }
        }
        if (helper.systemAccount() != address(ha0)) {
            helper.SetSystemAccount(address(ha0));
        }

        // Previous version deposited to EntryPoint, here we fund the acct directly
        if (address(ha0).balance < min_deposit) {
            payable(address(ha0)).transfer(min_deposit - address(ha0).balance);
        }

        vm.stopBroadcast();
        return [address(ept),address(helper), address(haf), address(ha0)];
    }
}
