// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "account-abstraction/v0_6/interfaces/INonceManager.sol";
import "openzeppelin-contracts-versions/v4_9/contracts/token/ERC20/utils/SafeERC20.sol";

contract HCHelper {
    using SafeERC20 for IERC20;

    // Response data is stored here by PutResponse() and then consumed by TryCallOffchain().
    // The storage slot must not be changed unless the corresponding code is updated in the Bundler.
    mapping(bytes32=>bytes)  ResponseCache;

    // Owner (creator) of this contract.
    address public owner;

    // BOBA token address
    address public tokenAddr;

    // Token amount required to purchase each prepaid credit (may be 0 for testing)
    uint256 public pricePerCall;

    // Account which is used to insert system error responses. Currently a single
    // address but could be extended to a list of authorized accounts if needed.
    address public systemAccount;

    // Data stored per RegisteredCaller
    struct callerInfo {
      address owner;
      string url;
      uint256 credits;
    }

    // Contracts which are allowed to use Hybrid Compute.
    mapping(address=>callerInfo) public RegisteredCallers;

    // AA EntryPoint
    address immutable entryPoint;

    // Constructor
    constructor(address _entryPoint, address _tokenAddr) {
	entryPoint = _entryPoint;
	tokenAddr = _tokenAddr;
    }

    // Initialize system addresses. Note - can be called again to change
    // these addresses if necessary.
    function initialize(address _owner, address _systemAccount) public {
        require(msg.sender == owner || address(0) == owner, "Only owner");
        owner = _owner;
        systemAccount = _systemAccount;
    }

    // Change the SystemAccount address (used for error responses)
    function SetSystemAccount(address _systemAccount) public {
        require(msg.sender == owner, "Only owner");
        systemAccount = _systemAccount;
    }

    // Temporary method, until an auto-registration protocol is developed.
    function RegisterUrl(address contract_addr, string calldata url) public {
        require(msg.sender == owner, "Only owner");
        RegisteredCallers[contract_addr].owner = msg.sender;
        RegisteredCallers[contract_addr].url = url;
    }

    // Set or change the per-call token price (0 is allowed). Does not affect
    // existing credit balances, only applies to new AddCredit() calls.
    function SetPrice(uint256 _pricePerCall) public {
        require(msg.sender == owner, "Only owner");
	pricePerCall = _pricePerCall;
    }

    // Purchase credits allowing the specified contract to perform HC calls.
    // The token cost is (pricePerCall() * numCredits) and is non-refundable
    function AddCredit(address contract_addr, uint256 numCredits) public {
        if (pricePerCall > 0) {
            uint256 tokenPrice = numCredits * pricePerCall;
            IERC20(tokenAddr).safeTransferFrom(msg.sender, address(this), tokenPrice);
	}
        RegisteredCallers[contract_addr].credits += numCredits;
    }

    // Allow the owner to withdraw tokens
    function WithdrawTokens(uint256 amount, address withdrawTo) public {
        require(msg.sender == owner, "Only owner");
        IERC20(tokenAddr).safeTransferFrom(address(this), withdrawTo, amount);
    }

    // Called from a HybridAccount contract, to populate the response which it will
    // subsequently request in TryCallOffchain()
    function PutResponse(bytes32 subKey, bytes calldata response) public {
        require(RegisteredCallers[msg.sender].owner != address(0), "Unregistered caller");
        require(response.length >= 32*4, "Response too short");

	(,, uint32 errCode,) = abi.decode(response,(address, uint256, uint32, bytes));
        require(errCode < 2, "invalid errCode for PutResponse()");

        bytes32 mapKey = keccak256(abi.encodePacked(msg.sender, subKey));
        ResponseCache[mapKey] = response;
    }

    // Allow the system to supply an error response for unsuccessful requests.
    // Any such response will only be retrieved if there was nothing supplied
    // by PutResponse()
    function PutSysResponse(bytes32 subKey, bytes calldata response) public {
        require(msg.sender == systemAccount, "Only systemAccount may call PutSysResponse");
        require(response.length >= 32*4, "Response too short");

	(,, uint32 errCode,) = abi.decode(response,(address, uint256, uint32, bytes));
        require(errCode >= 2, "PutSysResponse() may only be used for error responses");

        bytes32 mapKey = keccak256(abi.encodePacked(address(this), subKey));
        ResponseCache[mapKey] = response;
    }

    // Remove one or more map entries (only needed if response was not retrieved normally).
    function RemoveResponses(bytes32[] calldata mapKeys) public {
        require(msg.sender == systemAccount, "Only systemAccount may call RemoveResponses");
	for (uint32 i = 0; i < mapKeys.length; i++) {
	    delete(ResponseCache[mapKeys[i]]);
	}
    }

    // Try to retrieve an entry, also removing it from the mapping. This
    // function will check for stale entries by checking the nonce of the srcAccount.
    // Stale entries will return a "not found" condition.
    function getEntry(bytes32 mapKey) internal returns (bool, uint32, bytes memory) {
        bytes memory entry;
	bool found;
	uint32 errCode;
	bytes memory response;
	address srcAddr;
	uint256 srcNonce;

	entry = ResponseCache[mapKey];
	if (entry.length == 1) {
            // Used during state simulation to verify that a trigger request actually came from this helper contract
            revert("_HC_VRFY");
	} else if (entry.length != 0) {
	    found = true;
	    (srcAddr, srcNonce, errCode, response) = abi.decode(entry,(address, uint256, uint32, bytes));
	    uint192 nonceKey = uint192(srcNonce >> 64);

            INonceManager NM = INonceManager(entryPoint);
	    uint256 actualNonce = NM.getNonce(srcAddr, nonceKey);

	    if (srcNonce + 1 != actualNonce) {
	        // stale entry
		found = false;
		errCode = 0;
		response = "0x";
	    }

            delete(ResponseCache[mapKey]);
	}
	return (found, errCode, response);
    }

    // Make an offchain call to a pre-registered endpoint.
    function TryCallOffchain(bytes32 userKey, bytes memory req) public returns (uint32, bytes memory) {
        bool found;
	uint32 errCode;
        bytes memory ret;

        require(RegisteredCallers[msg.sender].owner != address(0), "Calling contract not registered");

	if (RegisteredCallers[msg.sender].credits ==  0) {
	    return (5, "Insufficient credit");
	}
	RegisteredCallers[msg.sender].credits -= 1;

        bytes32 subKey = keccak256(abi.encodePacked(userKey, req));
        bytes32 mapKey = keccak256(abi.encodePacked(msg.sender, subKey));

        (found, errCode, ret) = getEntry(mapKey);

	if (found) {
	    return (errCode, ret);
	} else {
	    // If no off-chain response, check for a system error response.
            bytes32 errKey = keccak256(abi.encodePacked(address(this), subKey));

	    (found, errCode, ret) = getEntry(errKey);
	    if (found) {
	        require(errCode >= 2, "invalid errCode");
	        return (errCode, ret);
	    } else {
	        // Nothing found, so trigger a new request.
                bytes memory prefix = "_HC_TRIG";
                bytes memory r2 = bytes.concat(prefix, abi.encodePacked(msg.sender, userKey, req));
                assembly {
                    revert(add(r2, 32), mload(r2))
	        }
	    }
	}
    }
}
