// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "lib/account-abstraction/contracts/samples/HybridAccount.sol";
import "lib/account-abstraction/contracts/test/TestAuctionSystem.sol";
import "lib/account-abstraction/contracts/test/TestCaptcha.sol";
import "lib/account-abstraction/contracts/test/TestCounter.sol";
import "lib/account-abstraction/contracts/test/TestRainfallInsurance.sol";
import "lib/account-abstraction/contracts/test/TestSportsBetting.sol";

contract LocalDeploy is Script {
    function run() external 
        returns (address[5] memory) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        address payable ha1Addr = payable(vm.envAddress("OC_HYBRID_ACCOUNT"));
        HybridAccount ha1;

        address[5] memory ret;

        vm.startBroadcast(deployerPrivateKey);

        ret[0] = address(new AuctionFactory(ha1Addr));
        ret[1] = address(new TestCaptcha(ha1Addr));
        ret[2] = address(new TestCounter(ha1Addr));
        ret[3] = address(new RainfallInsurance(ha1Addr));
        ret[4] = address(new SportsBetting(ha1Addr));

        vm.stopBroadcast();
        return ret;
    }
}
