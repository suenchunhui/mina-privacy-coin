# Mina zkApp: Privacy Coin

This project implements a privacy-preserving fungible token using mina protocol.
The token maintains 2 merkle trees for public and private balances, while also tracking the total minted supply.
Each merkle tree maintains leaf nodes that contains the address of the owner and balance.
Public tokens have known balances for each individual owner, and transaction details, while private tokens have masked owner address and balance.
Tokens are minted as public token, but can be transferred to and from private tokens, maintaining the total supply.

This code base serves as a proof-of-concept of a privacy token built on mina protocol.


## How to build
```
npm run build
```

## How to run main script

```
node build/src/main.js
```

## How to run tests

```
npm run test
npm run testw # watch mode
```

## How to run coverage

```
npm run coverage
```

## License

[Apache-2.0](LICENSE)
