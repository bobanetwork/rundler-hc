from random import *
from jsonrpcclient import request
from get_token_price.get_token_price_test import TestTokenPrice
from check_kyc.check_kyc_test import TestKyc
from add_sub_2.add_sub_2_test import TestAddSub2
from ramble.ramble_test import TestWordGuess
from verify_captcha.captcha_test import TestCaptcha
from rainfall_insurance.rainfall_insurance_test import test_rainfall_insurance, test_rainfall_insurance_payout
from userop_utils import *
from dotenv import load_dotenv
import os

load_dotenv()



# ===============================================

test_rainfall_insurance_payout(int(os.getenv("POLICY_ID")))

#TestCaptcha("0x123")

#TestTokenPrice("ETH")

#TestKyc(True)  # Success
#TestKyc(False)  # Fail

#TestAddSub2(2, 1)   # Success
#TestAddSub2(2, 10)  # Underflow error, asserted
#TestAddSub2(2, 3)   # Underflow error, handled internally
#TestAddSub2(7, 0)   # Not HC
#TestAddSub2(4, 1)   # Success again

# TestWordGuess(1, False)
# TestWordGuess(10, False)
# TestWordGuess(100, False)
# TestWordGuess(2, True)

showBalances()
balFinal_bnd = w3.eth.get_balance(bundler_addr)
balFinal_sa = EP.functions.getDepositInfo(SA.address).call()[0] + w3.eth.get_balance(SA.address)

print("Net balance changes", balFinal_bnd - balStart_bnd, balFinal_sa - balStart_sa,
      (balFinal_bnd + balFinal_sa) - (balStart_bnd + balStart_sa), (l1Fees + l2Fees))

userPaid = balStart_sa - balFinal_sa
bundlerProfit = balFinal_bnd - balStart_bnd
print("User account paid:", userPaid)
assert (userPaid > 0)
print("   Bundler profit:", bundlerProfit, 100*(bundlerProfit / userPaid), "%")
print("           L2 gas:", l2Fees, 100*(l2Fees / userPaid), "%")
print("           L1 fee:", l1Fees, 100*(l1Fees / userPaid), "%")
print("         Residual:", userPaid - (bundlerProfit + l2Fees + l1Fees))
