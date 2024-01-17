import * as fs from 'fs';
import prompts from  'prompts';
import {
    Field,
    Mina,
    PrivateKey,
    MerkleTree,
    MerkleWitness,
    PublicKey,
    Bool,
    MerkleMap,
} from 'o1js';
import { Coin } from './Coin.js';


//minting param
const mint_amt = Field(1000);
const zkAppAddress = ""  //coin contract addr
const senderKey58 = ""
const networkUrl = "https://proxy.berkeley.minaexplorer.com/graphql"

//randomized recipient
const user1_idx = 0n;
const user1_priv = PrivateKey.random();
const user1_pk = user1_priv.toPublicKey();
console.log(`recipient pub: ${user1_pk.toBase58()} priv: ${user1_priv.toBase58()}`);



//setup mina network
const minanetwork = Mina.Network(networkUrl)
Mina.setActiveInstance(minanetwork)
const senderKey = PrivateKey.fromBase58(senderKey58)
const senderAccount = senderKey.toPublicKey()
const zkAppInstance = new Coin(PublicKey.fromBase58(zkAppAddress));

//compile contract
console.log("compiling")
await Coin.compile();
console.log("done")

//setup params
const height = 32;
class MerkleWitness32 extends MerkleWitness(height) {}
const publicTree = new MerkleTree(height);
const tx2_leafWitness = new MerkleWitness32(
  publicTree.getWitness(user1_idx)
);

//send tx
const txn = await Mina.transaction({sender: senderAccount, fee: 1_000_000_000 /* 1 MINA */}, () => {
  zkAppInstance.mint(
    tx2_leafWitness,
    Bool(true), //emptyLeaf
    user1_pk, //recipient
    Field(0), //currentBal
    mint_amt //amount
  );
});
await txn.prove();
const rsl = await txn.sign([senderKey]).send();
console.log(`TX submitted: ${rsl.isSuccess} with hash: ${rsl.hash()}`);
