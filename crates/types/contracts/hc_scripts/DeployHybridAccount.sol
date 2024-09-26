// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "lib/account-abstraction-versions/v0_6/contracts/core/EntryPoint.sol";
import "lib/account-abstraction-versions/v0_6/contracts/core/HCHelper.sol";
import "lib/account-abstraction-versions/v0_6/contracts/samples/HybridAccountFactory.sol";
import "lib/account-abstraction-versions/v0_6/contracts/samples/SimpleAccountFactory.sol";

contract LocalDeploy is Script {
    function run() external
        returns (address) {
       // uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address ocOwner = vm.envAddress("OC_OWNER");
        uint256 deploySalt = vm.envOr("DEPLOY_SALT", uint256(0));
        address entryPointAddr = vm.envAddress("ENTRY_POINTS"); // Must be a single value despite the variable name
        address hafAddr = vm.envAddress("HA_FACTORY_ADDR");

        EntryPoint ept;
        HybridAccountFactory haf;
        HybridAccount ha1;

        uint112 min_deposit = 0.001 ether;

        vm.startBroadcast();

        ept = EntryPoint(payable(entryPointAddr));
        haf = HybridAccountFactory(hafAddr);

        address newAddr = haf.getAddress(ocOwner, deploySalt);
        if (newAddr.code.length > 0) {
            ha1 = HybridAccount(payable(newAddr));
        } else {
            ha1 = haf.createAccount(ocOwner,deploySalt);
        }

        (uint112 bal,,,,) = ept.deposits(address(ha1));
        if (bal < min_deposit) {
            ept.depositTo{value: min_deposit - bal}(address(ha1));
        }

        vm.stopBroadcast();
        return address(ha1);
    }
}
