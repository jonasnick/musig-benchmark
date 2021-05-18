# musig-benchmark

Benchmark the [libsecp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp/) implementations for MuSig key aggregation and signing.

This code exists only for experimental purposes and does not demonstrate how to use libsecp256k1 correctly - very much the opposite.

## Example

```
$ musig-bench keygen 10000000
pubkey: F137781B753B22F8CA5450A64104072DAC55A0CCE2B67B3797ED8131E1194D23
# total: 159.30s, gen: 91s, aggregation: 70s
```

```
$ musig-bench sign 5000
pubkey: CBFF2F6C3B33F4E993B6FD2D03EBD9D8A14EAA9C93E89F9EA605028FC15A0033
sig: FF80F94C860692607026515AA7DFD503C8B0EC4E2F49FEBCE3B7CC54D58752BF6362121E9DD320EEBC864EA1CF35857EB84A737FD53154660E5E22A7A565EF81
# 143.07s
```

## Building

The easiest way is to install the nix package manager and run

```
nix-build -A musig-benchmark
```

Alternatively you can make the Makefile work for you.
