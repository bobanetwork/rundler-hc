from random import *
from jsonrpcclient import request
from get_token_price.get_token_price_test import TestTokenPrice
from check_kyc.check_kyc_test import TestKyc
from add_sub_2.add_sub_2_test import TestAddSub2,TestRandomRequest
from ramble.ramble_test import TestWordGuess
#from verify_captcha.captcha_test import TestCaptcha
from auction_system.auction_system_test import TestAuction
from sports_betting.sports_betting_test import TestSportsBetting
from rainfall_insurance.rainfall_insurance_test import test_rainfall_insurance_purchase,test_rainfall_insurance_payout

from userop_utils import *
from dotenv import load_dotenv
import os

load_dotenv()

print("Starting Balances:")
show_balances()
balStart_bnd = w3.eth.get_balance(bundler_addr)
balStart_sa = EP.functions.getDepositInfo(u_account).call()[0] + w3.eth.get_balance(u_account)

print("TestCount(start)=", TC.functions.counters(u_account).call())
#print("TestFetchPrice(start)=", TFP.functions.counters(0).call())

# ===============================================

aa = aa_rpc(EP.address, w3, bundler_rpc)

TestAddSub2(aa, 2, 1)   # Success
exit(0)
TestAddSub2(aa, 2, 10)  # Underflow error, asserted
TestAddSub2(aa, 2, 3)   # Underflow error, handled internally
TestAddSub2(aa, 7, 0)   # Not HC
TestAddSub2(aa, 4, 1)   # Success again

TestWordGuess(aa, 1, False)
TestWordGuess(aa, 10, False)
#TestWordGuess(aa, 100, False)
TestWordGuess(aa, 2, True)

TestRandomRequest(aa, True)
TestRandomRequest(aa, False)

print("\n\n\n*** TestHybrid finished, will continue with extended tests in 10s ***")
time.sleep(10)

TestAuction(aa)

#policy_id = test_rainfall_insurance_purchase(aa)
#test_rainfall_insurance_payout(aa, policy_id)  # Calls external API; disabled by default

TestSportsBetting(aa)

#TestCaptcha("0x123")

# TestTokenPrice(aa, "ETH") # Calls external API; disabled by default

TestKyc(aa,True)
TestKyc(aa,False)

# ===============================================

print("TestCount(final)=", TC.functions.counters(u_account).call())
#print("TestFetchPrice(final)=", TFP.functions.counters(0).call())

print("\nFinal Balances:")
show_balances()
balFinal_bnd = w3.eth.get_balance(bundler_addr)
balFinal_sa = EP.functions.getDepositInfo(u_account).call()[0] + w3.eth.get_balance(u_account)

print("Net balance changes", balFinal_bnd - balStart_bnd, balFinal_sa - balStart_sa,
      (balFinal_bnd + balFinal_sa) - (balStart_bnd + balStart_sa), (gasFees['l1Fees'] + gasFees['l2Fees']))

userPaid = balStart_sa - balFinal_sa
bundlerProfit = balFinal_bnd - balStart_bnd
print("User account paid:", userPaid)
assert (userPaid > 0)
print("   Bundler profit:", bundlerProfit, 100*(bundlerProfit / userPaid), "%")
print("           L2 gas:", gasFees['l2Fees'], 100*(gasFees['l2Fees'] / userPaid), "%")
print("           L1 fee:", gasFees['l1Fees'], 100*(gasFees['l1Fees'] / userPaid), "%")
print("         Residual:", userPaid - (bundlerProfit + gasFees['l2Fees'] + gasFees['l1Fees']))
