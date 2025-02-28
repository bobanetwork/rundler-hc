# KYC Example

This example demonstrates how to integrate a **Know Your Customer (KYC)** verification process into a smart contract. The smart contract function takes an address and makes an off-chain call with that address. For simplicity, the off-chain function returns true, but in a real-world scenario, one would implement comprehensive KYC logic in this function.

## Overview
**1. Smart Contract**: A smart contract that includes a function to initiate KYC verification for a given address.

**2. Off-chain Function**: A function that performs KYC verification logic. In this example, it simply returns true if the address exists in an array.

**3. Integration**: The smart contract makes an off-chain call to the KYC function, which processes the address and returns the verification result.