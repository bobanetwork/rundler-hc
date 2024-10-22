// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./HybridAccount.sol";

contract TestKyc {
    address payable immutable helperAddr;

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }
    event FunctionCall(string name);

    function checkKyc(string calldata addressToCheck) internal returns (bool) {
        HybridAccount ha = HybridAccount(helperAddr);

        bytes memory req = abi.encodeWithSignature(
            "checkkyc(string)",
            addressToCheck
        );
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = ha.CallOffchain(userKey, req);

        if (error != 0) {
            revert(string(ret));
        }

        bool isKyced;
        (isKyced) = abi.decode(ret, (bool));
        return isKyced;
    }

    function openForEverybody(string calldata addressToCheck) public {
        emit FunctionCall("openForEverybody");
    }

    function openForKyced(string calldata addressToCheck) public {
        require (checkKyc(addressToCheck), "KYC check failed");
        emit FunctionCall("openForKyced");
    }
}
