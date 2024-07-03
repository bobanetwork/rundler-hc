# Word-Guessing Game Example
## Overview
This example demonstrates a word-guessing game. The game involves the following steps:

**1.** The user picks a four-letter word as their guess.

**2.** The user pays an amount based on the number of entries they wish to purchase. This wager is added to a pool.

**3.** An off-chain provider generates a random array of words and returns it as a string[].

**4.** If the user's guess appears in the list returned from the server, they win the entire pool.

**5.** A boolean flag allows the user to cheat by guaranteeing that the word "frog" will appear in the list.