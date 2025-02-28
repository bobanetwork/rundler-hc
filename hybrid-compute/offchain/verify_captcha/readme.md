# CAPTCHA Verification Example for Smart Contracts
This example demonstrates how to integrate CAPTCHA verification into your smart contract. Users must solve a CAPTCHA image as part of the verification process.

## How It Works

**1. CAPTCHA Generation**: A CAPTCHA image is generated, and the string displayed in the image is stored in a Redis database.  

**2. User Interaction**: The CAPTCHA image is displayed to the user (e.g., on a website). The user solves the CAPTCHA and submits their input.  

**3. Smart Contract Interaction**: The user's input is sent to the smart contract.  

**4. Off-Chain Verification**: The smart contract makes an off-chain call to a function that checks the user's input against the value stored in the Redis database.
Response: The function returns a success or error message to the smart contract based on the verification result.

## Running Redis in a Docker Container
To set up the Redis server in a Docker container, execute the following command in your terminal:

``` bash
docker run -d --name redis-stack-server -p 6379:6379 redis/redis-stack-server:late
```