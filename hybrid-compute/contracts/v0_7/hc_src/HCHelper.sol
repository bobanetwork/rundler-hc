// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "@account-abstraction/interfaces/INonceManager.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract HCHelper is ReentrancyGuard, UUPSUpgradeable, Initializable {
    using SafeERC20 for IERC20;

    event SystemAccountSet(address oldAccount, address newAccount);
    event RegisteredUrl(address contract_addr, string url);
    event TokenWithdrawal(address withdrawTo, uint256 amount);

    // Response data is stored here by PutResponse() and then consumed by TryCallOffchain().
    mapping(bytes32=>bytes)  ResponseCache;

    // AA EntryPoint
    address public immutable entryPoint;

    // Owner
    address public owner;

    // Account which is used to insert system error responses. Currently a single
    // address but could be extended to a list of authorized accounts if needed.
    address public systemAccount;

    // BOBA token address
    address public tokenAddr;

    // Token amount required to purchase each prepaid credit (may be 0 for testing)
    uint256 public pricePerCall;

    // Limit on the maximum credit balance which an account may hold, enforced
    // when purchasing credits. This allows system testing or temporary promotions
    // with a low or zero credit price.
    uint64 public maxCredits;

    // Data stored per RegisteredCaller
    struct callerInfo {
      address owner;
      string url;
      uint256 credits;
    }

    // Contracts which are allowed to use Hybrid Compute.
    mapping(address=>callerInfo) public RegisteredCallers;

    // Vesion identifier
    string public constant version = "0.5.0";

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }
    function _onlyOwner() internal view {
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    // Constructor
    constructor(address _entryPoint) {
	entryPoint = _entryPoint;
    }

    // Set the initial owner
    function initialize(address _owner) public virtual initializer {
        owner = _owner;
    }

    // Allow upgrade through UUPSUpgradeable
    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }

    // Change the SystemAccount address (used for error responses)
    function SetSystemAccount(address _systemAccount) public onlyOwner {
        emit SystemAccountSet(systemAccount, _systemAccount);
        systemAccount = _systemAccount;
    }

    // Temporary method, until an auto-registration protocol is developed.
    function RegisterUrl(address contract_addr, string calldata url) public onlyOwner {
        require(bytes(url).length > 0, "URL cannot be empty");
        RegisteredCallers[contract_addr].owner = msg.sender;
        RegisteredCallers[contract_addr].url = url;
        emit RegisteredUrl(contract_addr, url);
    }

    // This method allows a HybridAccount to register its offchain URL, creating an entry
    // in RegisteredCallers. The bundler will call a special method on the offchain url, passing
    // the address of the contract which is attempting to register it. The registration will
    // only succeed if the server sends a response accepting it.
    function SelfRegister(string calldata url) public returns (bool) {
        address contract_addr = msg.sender;
        bool success = true;

        require(contract_addr.codehash != keccak256(""), "SelfRegister must be called by a contract");
        if(bytes(url).length == 0) {
            RegisteredCallers[contract_addr].url = "";
            emit RegisteredUrl(contract_addr, "");
        } else {
            // This is a modified subset of TryCallOffchain()
            bytes32 userKey = keccak256(abi.encodePacked("_register_", msg.sender));
            bytes memory req = abi.encodeWithSignature("_register(address,string)", contract_addr, url);

            bytes32 subKey = keccak256(abi.encodePacked(userKey, req));
            bytes32 mapKey = keccak256(abi.encodePacked(msg.sender, subKey));

            bool found;
	    uint32 errCode;
            bytes memory ret;

            (found, errCode, ret) = getEntry(mapKey);

	    if (found) {
                if (errCode == 0) {
	            bool reg_success = abi.decode(ret, (bool));
                    if (reg_success) {
                        RegisteredCallers[contract_addr].owner = contract_addr;
                        RegisteredCallers[contract_addr].url = url;
                        emit RegisteredUrl(contract_addr, url);
                    }
                    return reg_success;
                }
                return false;
	    } else {
	        // If no off-chain response, check for a system error response.
                bytes32 errKey = keccak256(abi.encodePacked(address(this), subKey));

	        (found, errCode, ret) = getEntry(errKey);
	        if (found) {
	            return false;
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

    // Reassign ownership of a registered caller. Not needed under normal circumstances.
    function ReassignOwner(address contract_addr, address new_owner) public {
        require(new_owner != address(0), "Must supply a new_owner");
        require(RegisteredCallers[contract_addr].owner != address(0), "Caller is not registered");
        require(msg.sender == RegisteredCallers[contract_addr].owner, "Only existing owner may reassign");
        RegisteredCallers[contract_addr].owner = new_owner;
    }

    // Set or change the per-call token price (0 is allowed), token,
    // and maximum credit balance. Does not affect existing balances,
    // only new AddCredit() purchases.
    function SetPaymentInfo(address _tokenAddr, uint256 _pricePerCall, uint64 _maxCredits) public onlyOwner {
	tokenAddr = _tokenAddr;
	pricePerCall = _pricePerCall;
        maxCredits = _maxCredits;
    }

    // Purchase credits allowing the specified contract to perform HC calls.
    // The token cost is (pricePerCall() * numCredits) and is non-refundable
    function AddCredit(address contract_addr, uint256 numCredits) public nonReentrant {
        require(tokenAddr != address(0), "Payment info not initialized");
        uint256 tokenPrice = numCredits * pricePerCall;
        RegisteredCallers[contract_addr].credits += numCredits;
        require(RegisteredCallers[contract_addr].credits <= maxCredits, "Purchase exceeds maxCredits limit");
        IERC20(tokenAddr).safeTransferFrom(msg.sender, address(this), tokenPrice);
    }

    // Allow the owner to withdraw tokens
    function WithdrawTokens(uint256 amount, address withdrawTo) public onlyOwner nonReentrant {
        emit TokenWithdrawal(withdrawTo, amount);
        IERC20(tokenAddr).safeTransfer(withdrawTo, amount);
    }

    // Called from a HybridAccount contract, to populate the response which it will
    // subsequently request in TryCallOffchain()
    function PutResponse(bytes32 subKey, bytes calldata response) public {
        require(RegisteredCallers[msg.sender].owner != address(0), "Unregistered caller");
        require(response.length % 32 == 0, "Response not properly encoded");
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
        delete(ResponseCache[mapKey]);

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
	}
	return (found, errCode, response);
    }

    // Make an offchain call to a pre-registered endpoint.
    function TryCallOffchain(bytes32 userKey, bytes memory req) public returns (uint32, bytes memory) {
        bool found;
	uint32 errCode;
        bytes memory ret;

        require(RegisteredCallers[msg.sender].owner != address(0), "Calling contract not registered");
        require(req.length % 32 == 4, "Request must be ABI-encoded with selector");

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

    // Returns the slot index of ResponseCache, needed by the bundler.
    // This index is affected by the OpenZeppelin libraries like Ownable.
    function ResponseSlot() public pure returns (uint256 ret) {
        assembly {
            ret := ResponseCache.slot
        }
    }
}
