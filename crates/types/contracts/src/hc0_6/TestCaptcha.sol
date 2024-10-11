// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./HybridAccount.sol";

contract TestCaptcha is Ownable {
    address payable immutable helperAddr;
    uint256 constant public nativeFaucetAmount = 0.01 ether;
    uint256 constant public waitingPeriod = 1 days;
    IERC20 public token;

    mapping(address => uint256) public claimRecords;

    uint256 private constant SAFE_GAS_STIPEND = 6000;

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }

    event Withdraw(address receiver, uint256 nativeAmount);

    receive() external payable {}

    function withdraw(uint256 _nativeAmount) public onlyOwner {
        (bool sent, ) = msg.sender.call{
            gas: SAFE_GAS_STIPEND,
            value: _nativeAmount
        }("");
        require(sent, "Failed to send native Ether");

        emit Withdraw(msg.sender, _nativeAmount);
    }

    function verifyCaptcha(
        address _to,
        bytes32 _uuid,
        string memory _key
    ) private returns (bool) {
        HybridAccount ha = HybridAccount(helperAddr);

        bytes memory req = abi.encodeWithSignature(
            "verifyCaptcha(string,string,string)",
             _to,
            _uuid,
            _key
        );
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = ha.CallOffchain(userKey, req);

        if (error != 0) {
            revert(string(ret));
        }

        bool isVerified;
        (isVerified) = abi.decode(ret, (bool));
        return isVerified;
    }

 function getTestnetETH(
        bytes32 _uuid,
        string memory _key,
        address _to) external {
        require(claimRecords[_to] + waitingPeriod <= block.timestamp, 'Invalid request');
        require(verifyCaptcha(_to, _uuid, _key), "Invalid captcha");
        claimRecords[_to] = block.timestamp;

        (bool sent,) = (_to).call{gas: SAFE_GAS_STIPEND, value: nativeFaucetAmount}("");
        require(sent, "Failed to send native");
    }
}
