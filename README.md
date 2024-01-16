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

## How to run test
End-to-end test for `Coin.ts` contract
```
npm run test
```

End-to-end test for `Sales.ts` contract
```
npm run test_sales
```

## How to deploy
Create a zkapp config:
```
npx zk config
```
1. Give a config name
2. Provide Mina GraphQL API: `https://proxy.berkeley.minaexplorer.com/graphql`
3. Set transaction fee as `1`
4. Pick a feepayer key (`zkapp` will create one if needed)

Fund the feepayer key using the link provided:
`https://faucet.minaprotocol.com/?address=<FEEPAYER_KEY>&?explorer=minaexplorer`

Run the deploy command:
```
npx zk deploy <config name>
```
1. Choose the contract `Coin`
2. Confirm the deployment with `yes`
3. Wait for a few minutes for the transaction to be `applied` in the provided explorer link

## License

[Apache-2.0](LICENSE)
