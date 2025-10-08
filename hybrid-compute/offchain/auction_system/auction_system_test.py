"""Test the Hybrid Compute auction-system example"""
from eth_abi import abi as ethabi
from web3 import Web3

def test_auction(t):
    """Test the Hybrid Compute auction-system example"""
    print("\n  - - - - TestAuction() - - - -")
    t.load_contract('TestAuctionSystem')

    start_auction_call = t.selector("createAuction(uint256,address)") + \
        ethabi.encode(['uint256', 'address'], [300, t.client_addr])

    op = t.build_op('TestAuctionSystem', 0, start_auction_call)

    (success, op) = t.estimate_op(op)
    assert success

    rcpt = t.submit_op(op)
    topic = Web3.keccak(text="AuctionCreated(uint256,address)")
    event = t.parse_receipt(rcpt, topic)
    (auction_id, _auction_address) = ethabi.decode(['uint256', 'address'],
        Web3.to_bytes(hexstr=event[1]))
    bid(t, auction_id)
    print("TestAuction end")

def bid(t, auction_id):
    """Place a bid"""
    print("\n  - - - - bid() - - - -")
    bid_call = t.selector("bid(uint256)") + ethabi.encode(['uint256'], [auction_id])

    op = t.build_op('TestAuctionSystem', 6, bid_call)

    (success, op) = t.estimate_op(op)
    assert success

    rcpt = t.submit_op(op)
    t.parse_receipt(rcpt)

    print("TestAuction end")
