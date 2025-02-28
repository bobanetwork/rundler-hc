# Add-Sub Example
The `count` function in the `TestCounter` smart contract takes two integers, `a` and `b`, as inputs. These integers are sent to an off-chain function, which performs arithmetic operations and returns a pair of numbers representing the sum and difference of the two parameters.

## Overview
**1. Smart Contract**: A smart contract that includes a function (count) to perform arithmetic operations by making off-chain calls.

**2. Off-chain Function**: A function that calculates the sum and difference of two integers. If the second integer is greater than the first, it returns an error due to subtraction underflow.

**3. Integration**: The smart contract makes an off-chain call to the arithmetic function, which processes the integers and returns the results (sum and difference) or an error.