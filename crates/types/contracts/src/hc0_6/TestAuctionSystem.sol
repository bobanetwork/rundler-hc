// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./HybridAccount.sol";

contract AuctionFactory {
    uint256 public auctionCount = 0;
    mapping(uint256 => Auction) public auctions;

    event AuctionCreated(uint256 auctionId, address auctionAddress);
    event AuctionEnded(uint256 auctionId, address winner, uint256 amount);

    struct Auction {
        address highestBidder;
        uint256 highestBid;
        uint256 endTime;
        address payable beneficiary;
        bool ended;
    }

    address payable immutable helperAddr;

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }

    modifier auctionExists(uint256 auctionId) {
        require(auctions[auctionId].beneficiary != address(0), "Auction does not exist");
        _;
    }

    function createAuction(uint256 _biddingTime, address payable _beneficiary) public {
        auctionCount++;
        auctions[auctionCount] = Auction({
            highestBidder: address(0),
            highestBid: 0,
            endTime: block.timestamp + _biddingTime,
            beneficiary: _beneficiary,
            ended: false
        });
        emit AuctionCreated(auctionCount, address(this));
    }

    function bid(uint256 auctionId) public payable auctionExists(auctionId) {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp < auction.endTime, "Auction already ended.");
        require(msg.value > auction.highestBid, "There already is a higher bid.");
        require(verifyBidder(), "Bidder not verified.");

        if (auction.highestBidder != address(0)) {
            payable(auction.highestBidder).transfer(auction.highestBid);
        }

        auction.highestBidder = msg.sender;
        auction.highestBid = msg.value;
    }

    function verifyBidder() private returns (bool) {
        HybridAccount ha = HybridAccount(helperAddr);

        bytes memory req = abi.encodeWithSignature(
            "verifyBidder(address)",
            msg.sender
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

    function endAuction(uint256 auctionId) public auctionExists(auctionId) {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp >= auction.endTime, "Auction not yet ended.");
        require(!auction.ended, "Auction end already called.");

        auction.ended = true;
        emit AuctionEnded(auctionId, auction.highestBidder, auction.highestBid);

        auction.beneficiary.transfer(auction.highestBid);
    }

    function getHighestBid(uint256 auctionId) public view auctionExists(auctionId) returns (uint256) {
        return auctions[auctionId].highestBid;
    }

    function getHighestBidder(uint256 auctionId) public view auctionExists(auctionId) returns (address) {
        return auctions[auctionId].highestBidder;
    }

    function getAuctionEndTime(uint256 auctionId) public view auctionExists(auctionId) returns (uint256) {
        return auctions[auctionId].endTime;
    }

    function isAuctionEnded(uint256 auctionId) public view auctionExists(auctionId) returns (bool) {
        return auctions[auctionId].ended;
    }
}
