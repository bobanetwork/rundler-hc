// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./HybridAccount.sol";

contract TestTokenPrice {
    mapping(uint256 => uint256) public counters;
    address payable immutable helperAddr;

    event PriceQuote(string, string);

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
        counters[0] = 100;
    }

    function fetchPrice(
        string calldata token
    ) public returns (string memory) {
        HybridAccount ha = HybridAccount(payable(helperAddr));
        string memory price;

        bytes memory req = abi.encodeWithSignature("getprice(string)", token);
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = ha.CallOffchain(userKey, req);

        if (error != 0) {
            revert(string(ret));
        }

        (price) = abi.decode(ret, (string));
        emit PriceQuote(token, price);
        return price;
    }
}
