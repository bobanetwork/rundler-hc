from eth_abi import abi as ethabi
from userop_utils import *

def TestAuction(aa):
    print("\n  - - - - TestAuction() - - - -")

    start_auction_call = selector("createAuction(uint256,address)") + ethabi.encode(['uint256', 'address'], [300, SA.address])

    op = aa.build_op(SA.address, TEST_AUCTION.address, 0, start_auction_call, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    topic = Web3.keccak(text="AuctionCreated(uint256,address)")
    event = ParseReceipt(rcpt, topic)
    (auctionId, auctionAddress) = ethabi.decode(['uint256', 'address'], Web3.to_bytes(hexstr=event[1]))
    bid(aa, auctionId)
    print("TestAuction end")

def bid(aa, auctionId):
    print("\n  - - - - bid() - - - -")
    bid_call = selector("bid(uint256)") + ethabi.encode(['uint256'], [auctionId])

    op = aa.build_op(SA.address, TEST_AUCTION.address, 6, bid_call, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("TestAuction end")
