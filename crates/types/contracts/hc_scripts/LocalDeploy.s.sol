// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "lib/account-abstraction-versions/v0_6/contracts/core/EntryPoint.sol";
import "lib/account-abstraction-versions/v0_6/contracts/core/HCHelper.sol";
import "lib/account-abstraction-versions/v0_6/contracts/samples/HybridAccountFactory.sol";
import "lib/account-abstraction-versions/v0_6/contracts/samples/SimpleAccountFactory.sol";

contract LocalDeploy is Script {
    function run() external
        returns (address[5] memory) {
        address deployAddr = vm.envAddress("DEPLOY_ADDR");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address hcSysOwner = vm.envAddress("HC_SYS_OWNER");
        require (hcSysOwner != address(0), "HC_SYS_OWNER not set");
        uint256 deploySalt = vm.envOr("DEPLOY_SALT",uint256(0)); // Change this to force redeployment of contracts

        address bobaAddr = vm.envOr("BOBA_TOKEN", 0x4200000000000000000000000000000000000023);

        EntryPoint ept;
        HCHelper helper;
        SimpleAccountFactory saf;
        HybridAccountFactory haf;
        HybridAccount ha0;

        bytes32 salt_val = bytes32(deploySalt);
        uint112 min_deposit = 0.001 ether;

        vm.startBroadcast(deployerPrivateKey);

        {  // Limit variable scope to avoid "stack too deep"
            address entryPointAddr = vm.envOr("ENTRY_POINTS", 0x0000000000000000000000000000000000000000); // Must be a single value despite the variable name
            if (entryPointAddr != address(0) && entryPointAddr.code.length > 0) {
                ept = EntryPoint(payable(entryPointAddr));
            } else {
                ept = new EntryPoint{salt: salt_val}();
            }
        }
        {
            address helperAddr = vm.envOr("HC_HELPER_ADDR", 0x0000000000000000000000000000000000000000);
            if (helperAddr != address(0) && helperAddr.code.length > 0) {
                helper = HCHelper(helperAddr);
            } else {
                helper = new HCHelper{salt: salt_val}(address(ept), bobaAddr);
            }
        }
        {
            address safAddr = vm.envOr("SA_FACTORY_ADDR", 0x0000000000000000000000000000000000000000);
            if (safAddr != address(0) && safAddr.code.length > 0) {
                saf = SimpleAccountFactory(safAddr);
            } else {
                saf = new SimpleAccountFactory(ept);
            }
        }
        {
            address hafAddr = vm.envOr("HA_FACTORY_ADDR", 0x0000000000000000000000000000000000000000);
            if (hafAddr != address(0) && hafAddr.code.length > 0) {
                haf = HybridAccountFactory(hafAddr);
            } else {
                haf = new HybridAccountFactory(ept, address(helper));
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
            helper.initialize(deployAddr, address(ha0));
        }

        (uint112 bal,,,,) = ept.deposits(address(ha0));
        if (bal < min_deposit) {
            ept.depositTo{value: min_deposit - bal}(address(ha0));
        }

        vm.stopBroadcast();
        return [address(ept),address(helper), address(saf), address(haf), address(ha0)];
    }
}
