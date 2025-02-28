# AA Hybrid Compute

This repository contains a modified version of the Rundler application which implements a Hybrid Compute capability. Calls to a special `HCHelper` contract are intercepted during the gas-estimation phase, triggering the bundler to make a JSON-RPC call to an external server. The server response is wrapped into a `UserOperation` structure and is front-run ahead of the initiating `UserOperation` in order to populate a response cache in the contract. The gas estimation is then re-run, providing the user with totals reflecting the cost of both their operation and the associated one to populate the cache (implemented by charging extra `preVerificationGas`).

Additional information may be found at https://docs.boba.network/hc and https://github.com/bobanetwork/aa-hc-example.

# Changelog

* v0.2.0

This version ports the hybrid-compute features on top of the upstream rundler 0.3.0 release, with a restriction that the functionality is only implemented for version 0.6 of the AA EntryPoint contract. The address of the EntryPoint contract is no longer configurable.

* v0.1.0

This tag was retroactively reserved for the initial version deployed to the testnet as "sepolia-rcN" images. It was derived from an arbitrary commit in the upstream rundler repository (7f34a69c).
