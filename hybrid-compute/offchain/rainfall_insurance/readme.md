# Rainfall Insurance
This example demonstrates how to create a rainfall insurance smart contract, where users can buy insurance policies that pay out if a certain amount of rainfall occurs. The smart contract interacts with off-chain services to fetch rainfall data.

## Prerequisites
The offchain-function relies on a free [weather-api](https://www.weatherapi.com/). Therefore you need to generate an `API-KEY` and set it in the `rainfall_insurance_offchain.py` file.

## Overview
**1. Insurance Purchase**: Users buy an insurance policy by providing a premium and specifying the trigger rainfall level and the city for which the policy applies.

**2. Rainfall Update**: The smart contract can update rainfall data for a city by making an off-chain call to retrieve the latest data.

**3. Claim Payout**: Users can claim their payout if the actual rainfall meets or exceeds the trigger level specified in their policy.

# Smart Contract Functionality
## Buy Insurance
Users can purchase an insurance policy by providing the following:

- Trigger Rainfall Level: The amount of rainfall (in mm) that triggers the payout.
- City: The city for which the policy applies.
- Premium: The amount paid by the user to purchase the policy.
A unique policy ID is generated using a combination of the user's address, city, and timestamp.

## Update Rainfall
The smart contract can request updated rainfall data for a specified city by making an off-chain call. The retrieved data is stored in a Redis database for later verification.

## Check and Payout
When a user wants to claim their payout, the smart contract:

- Verifies that the policy has not already been claimed.
- Checks the stored rainfall data to see if the trigger condition is met.
- If the condition is met, the payout amount is transferred to the user's address.

## Off-chain Operations
To fetch real-time weather data, we call an off-chain function, which provides us such information.

## Info
The `BuyInsurance` step actually happens in the `deploy.py` file and not in the `rainfall_insurance_test.py` file. The `deploy.py` file call the `buyInsurance` function, which emits an event with the generated `PolicyId`. We write that ID to the .env file which then get's read by the `userop.py` file which cals the test-function with it the ID.