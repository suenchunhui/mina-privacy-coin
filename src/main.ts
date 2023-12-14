import 'dotenv/config';
import { Coin } from './Coin.js';
import MerkleListener from './server.js';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  AccountUpdate,
  MerkleTree,
  MerkleWitness,
  PublicKey,
  Poseidon,
  Bool,
  MerkleMap,
  MerkleMapWitness,
  Nullifier,
  Signature,
} from 'o1js';
import axios from 'axios';

const transactionFee = 100_000_000;
const api_port = 30001;
let senderKey: PrivateKey, senderAccount: PublicKey;
let Local;
if (process.env.NetworkURL && process.env.SenderPrivateKey) {
  const MinaNetwork = Mina.Network(process.env.NetworkURL);
  Mina.setActiveInstance(MinaNetwork);
  console.log('Using network: ' + process.env.NetworkURL);

  senderKey = PrivateKey.fromBase58(process.env.SenderPrivateKey);
  senderAccount = senderKey.toPublicKey();
} else {
  const useProof = false;
  Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
  Mina.setActiveInstance(Local);
  console.log('Using local network');

  senderKey = Local.testAccounts[1].privateKey;
  senderAccount = Local.testAccounts[1].publicKey;
}

// --- additional functions ---
function publicLeaf(recipient: PublicKey, amount: Field): Field {
  const pkfields = recipient.toFields();
  return Poseidon.hash([pkfields[0], pkfields[1], amount]);
}

function privateUTXOLeaf(
  recipient: PublicKey,
  amount: Field,
  nonce: Field
): Field {
  const pkfields = recipient.toFields();
  return Poseidon.hash([pkfields[0], pkfields[1], amount, nonce]);
}

function nullifierKey(recipient: PublicKey, utxoIndex: Field): Field {
  const pkfields = recipient.toFields();
  return Poseidon.hash([pkfields[0], pkfields[1], utxoIndex]);
}

//tree defn
const height = 32;
class MerkleWitness32 extends MerkleWitness(height) {}

// --- tree init ---
const publicTree = new MerkleTree(height);
const privateTree = new MerkleTree(height);
const nullifierTree = new MerkleMap();
const initialPublicRoot = publicTree.getRoot();
const initialPrivateRoot = privateTree.getRoot();
const initialNullifierRoot = nullifierTree.getRoot();

let merkleListener;

// --- init users ---
// Create a public/private key pair. For users
//public users
const user1_priv = PrivateKey.random();
const user1_pk = user1_priv.toPublicKey();
const user2_priv = PrivateKey.random();
const user2_pk = user2_priv.toPublicKey();

//private users
const pv_user3_priv = PrivateKey.random();
const pv_user3_pk = pv_user3_priv.toPublicKey();
const pv_user4_priv = PrivateKey.random();
const pv_user4_pk = pv_user4_priv.toPublicKey();

//init contract
let zkAppAddress;
let zkAppInstance: Coin;
if (process.env.NetworkURL && process.env.ZkAppAddress) {
  // --- use deployed contract ---
  zkAppAddress = PrivateKey.fromBase58(process.env.ZkAppAddress).toPublicKey();
  zkAppInstance = new Coin(zkAppAddress);
  console.log('Using deployed contract at: ' + process.env.ZkAppAddress);
} else {
  // --- deploy new contract ----
  // Create a public/private key pair. The public key is your address and where you deploy the zkApp to
  const zkAppPrivateKey = PrivateKey.random();
  zkAppAddress = zkAppPrivateKey.toPublicKey();
  let deployerAccount: PublicKey, deployerKey: PrivateKey;
  if (process.env.deployerPrivateKey) {
    deployerKey = PrivateKey.fromBase58(process.env.deployerPrivateKey);
    deployerAccount = deployerKey.toPublicKey();
  } else if (Local) {
    deployerKey = Local.testAccounts[0].privateKey;
    deployerAccount = Local.testAccounts[0].publicKey;
  } else {
    console.log('Error: missing deployer key on non-local chain');
    process.exit(-1);
  }

  // --- create an instance of Coin - and deploy it to zkAppAddress ---
  zkAppInstance = new Coin(zkAppAddress);
  const deployTxn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    zkAppInstance.deploy();
  });
  await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
}
// -------------------- initState --------------------------------

console.log('--- deploy & init state ---');

merkleListener = new MerkleListener(zkAppInstance, height, api_port);

const txn1 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.initState(
    initialPublicRoot,
    initialPrivateRoot,
    initialNullifierRoot
  );
});
await txn1.prove();
await txn1.sign([senderKey]).send();

const publicTreeRoot1 = zkAppInstance.publicTreeRoot.get();
console.log('tree state:           ', initialPublicRoot.toString());
console.log('tree state after txn1:', publicTreeRoot1.toString());

// ----------------------- tx2 public mint -----------------------------

console.log('--- tx2 public mint ---');

const user1_idx = BigInt(2);
const mint_amt = Field(10);

//update off-chain tree
const leafWitness = new MerkleWitness32(publicTree.getWitness(user1_idx));

const txn2 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.mint(
    leafWitness,
    Bool(true), //emptyLeaf
    user1_pk, //recipient
    Field(0), //currentBal
    mint_amt //amount
  );
});
await txn2.prove();
const d = await txn2.sign([senderKey]).send();

//events
await merkleListener.fetchEvents();

const t2_leaf_update_idx =
  txn2.transaction.accountUpdates[0].body.events.data[1][1];
const t2_leaf_update_data =
  txn2.transaction.accountUpdates[0].body.events.data[0][1];
console.log(
  `leaf update: index: ${t2_leaf_update_idx} data: ${t2_leaf_update_data}`
);

//offline merkle tree update
const t2_leaf_update_data_offline = publicLeaf(user1_pk, mint_amt);
console.log(`leaf data computation:      ${t2_leaf_update_data_offline}`);
publicTree.setLeaf(user1_idx, publicLeaf(user1_pk, mint_amt));

/*const tmp = await axios.get(`http://localhost:${api_port}/public/root`);
console.log(tmp);
const tmp2 = await axios.get(`http://localhost:${api_port}/public/witness?index=2`);
console.log(tmp2.data);*/

//compare merkle root
const publicTreeRoot2 = zkAppInstance.publicTreeRoot.get();
console.log('tree state (offline): ', publicTree.getRoot().toString());
console.log('tree state after txn2:', publicTreeRoot2.toString());

// ----------------------- tx3 public transfer -----------------------------

console.log('--- tx3 public-public transfer ---');

const user2_idx = BigInt(6);
const tx3_transfer_amt = Field(7);

const senderWitness = new MerkleWitness32(publicTree.getWitness(user1_idx));
const recipientWitness = new MerkleWitness32(publicTree.getWitness(user2_idx));

const sig3 = Signature.create(user1_priv, [
  publicTree.getRoot(),
  tx3_transfer_amt,
]);

const txn3 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.transfer(
    //sender
    senderWitness,
    user1_pk,
    mint_amt, //sender bal
    sig3, //signature

    //recipient
    Bool(true), //emptyRecipientLeaf
    recipientWitness,
    user2_pk,
    Field(0), //recipientBal

    //amount
    tx3_transfer_amt
  );
});

await txn3.prove();
await txn3.sign([senderKey]).send();

await merkleListener.fetchEvents();

//update off-chain tree
const t3_sender_update_data_offline = publicLeaf(
  user1_pk,
  mint_amt.sub(tx3_transfer_amt)
);
const t3_recipient_update_data_offline = publicLeaf(user2_pk, tx3_transfer_amt);
publicTree.setLeaf(user1_idx, t3_sender_update_data_offline);
publicTree.setLeaf(user2_idx, t3_recipient_update_data_offline);

const publicTreeRoot3 = zkAppInstance.publicTreeRoot.get();
console.log('tree root (offline): ', publicTree.getRoot().toString());
console.log('tree root after txn3:', publicTreeRoot3.toString());

let user1_bal = mint_amt.sub(tx3_transfer_amt);
let user2_bal = Field(tx3_transfer_amt);

// ----------------------- tx4 init private -----------------------------

let pv_user3_bal = Field(0);

// console.log('--- tx4 init private (pv_user3) ---');

// const prv_user3_idx = BigInt(11);
// const pv_user3_blindNonce = Field(283476); //TODO, to use random

// let pv_user3_blindBal = Field(pv_user3_blindNonce);
// const pv_user3_blindHash = Poseidon.hash([pv_user3_blindNonce]);

// const witness4 = new MerkleWitness32(privateTree.getWitness(prv_user3_idx));

// const txn4 = await Mina.transaction(senderAccount, () => {
//   zkAppInstance.initPrivate(witness4, pv_user3_pk, pv_user3_blindNonce);
// });

// await txn4.prove();
// await txn4.sign([senderKey]).send();

// await merkleListener.fetchEvents();

// //update off-chain tree
// const t4_update_data_offline = privateLeaf(
//   pv_user3_pk,
//   Field(0),
//   pv_user3_blindNonce
// );
// privateTree.setLeaf(prv_user3_idx, t4_update_data_offline);

// const privateTreeRoot4 = zkAppInstance.privateTreeRoot.get();
// console.log('private tree root (offline): ', privateTree.getRoot().toString());
// console.log('private tree root after txn4:', privateTreeRoot4.toString());

// ----------------------- tx5 public->private transfer -----------------------------

console.log('--- tx5 public to private transfer ---');

const tx5_transfer_amt = Field(5);
const senderWitness5 = new MerkleWitness32(publicTree.getWitness(user2_idx));
let tx5_nonce = Field(Math.floor(Math.random() * 100000)); //TODO not-crypto secure random
let utxo_index = 0n;
let utxoWitness = new MerkleWitness32(privateTree.getWitness(utxo_index));
const sig5 = Signature.create(user2_priv, [
  publicTree.getRoot(),
  privateTree.getRoot(),
  tx5_transfer_amt,
]);

const txn5 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.transferToPrivate(
    //sender
    senderWitness5,
    user2_pk,
    user2_bal,
    sig5, //signature

    //recipient
    pv_user3_pk, //recipient
    tx5_nonce, //nonce
    utxoWitness, //newPrivateWitness

    //amount
    tx5_transfer_amt
  );
});

await txn5.prove();
await txn5.sign([senderKey]).send();

await merkleListener.fetchEvents();

//update off-chain tree
const t5_sender_update_data_offline = publicLeaf(
  user2_pk,
  user2_bal.sub(tx5_transfer_amt)
);
publicTree.setLeaf(user2_idx, t5_sender_update_data_offline);
const t5_recipient_update_data_offline = privateUTXOLeaf(
  pv_user3_pk,
  tx5_transfer_amt,
  tx5_nonce
);
privateTree.setLeaf(utxo_index, t5_recipient_update_data_offline);

user2_bal = user2_bal.sub(tx5_transfer_amt);
pv_user3_bal = tx5_transfer_amt;

const publicTreeRoot5 = zkAppInstance.publicTreeRoot.get();
console.log('public tree root (offline): ', publicTree.getRoot().toString());
console.log('public tree root after txn5:', publicTreeRoot5.toString());

const privateTreeRoot5 = zkAppInstance.privateTreeRoot.get();
console.log('private tree root (offline): ', privateTree.getRoot().toString());
console.log('private tree root after txn5:', privateTreeRoot5.toString());

// ----------------------- tx6 init private -----------------------------

// console.log('--- tx6 init private (pv_user4) ---');

// const prv_user4_idx = BigInt(12);
// const pv_user4_blindNonce = Field(123123); //TODO, to use random
// let pv_user4_bal = Field(0);
// let pv_user4_blindBal = Field(pv_user4_blindNonce);
// const pv_user4_blindHash = Poseidon.hash([pv_user4_blindNonce]);

// const witness6 = new MerkleWitness32(privateTree.getWitness(prv_user4_idx));

// const txn6 = await Mina.transaction(senderAccount, () => {
//   zkAppInstance.initPrivate(witness6, pv_user4_pk, pv_user4_blindNonce);
// });

// await txn6.prove();
// await txn6.sign([senderKey]).send();

// await merkleListener.fetchEvents();

// //update off-chain tree
// const t6_update_data_offline = privateLeaf(
//   pv_user4_pk,
//   Field(0),
//   pv_user4_blindNonce
// );
// privateTree.setLeaf(prv_user4_idx, t6_update_data_offline);

// const privateTreeRoot6 = zkAppInstance.privateTreeRoot.get();
// console.log('private tree root (offline): ', privateTree.getRoot().toString());
// console.log('private tree root after txn6:', privateTreeRoot6.toString());

// ----------------------- tx7 private->private transfer -----------------------------

console.log('--- tx7 private to private transfer ---');

const tx7_transfer_amt = Field(3);
let utxo0 = privateUTXOLeaf(pv_user3_pk, tx5_transfer_amt, tx5_nonce);
let _temp = Nullifier.createTestNullifier([utxo0], pv_user3_priv);
// console.log("json_nullifier ", _temp);
let nullifer0 = Nullifier.fromJSON(_temp);
nullifer0.verify([utxo0]);
const temppk = pv_user3_pk.toFields();
let utxoIndex = Field(0);
const calculatedKey = nullifierKey(pv_user3_pk, utxoIndex);
const nulliferWitness0 = nullifierTree.getWitness(calculatedKey);
const sig7 = Signature.create(pv_user3_priv, [
  privateTree.getRoot(),
  tx5_transfer_amt,
  tx5_transfer_amt,
]);

const utxoWitness0 = new MerkleWitness32(privateTree.getWitness(0n));
const newPrivateWitness0 = new MerkleWitness32(privateTree.getWitness(1n));
const tx7_recipientNonce0 = Field(Math.floor(Math.random() * 100000));
const t7_recipient_leaf0 = privateUTXOLeaf(
  pv_user4_pk,
  tx7_transfer_amt,
  tx7_recipientNonce0
);
privateTree.setLeaf(1n, t7_recipient_leaf0);
let newPrivateWitness1 = new MerkleWitness32(privateTree.getWitness(2n));
let tx7_recipientNonce1 = Field(Math.floor(Math.random() * 100000));

const txn7 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.transferPrivateToPrivate(
    //sender
    pv_user3_pk,

    //utxo0 to spend
    nullifer0,
    nulliferWitness0,
    utxoWitness0,
    tx5_transfer_amt,
    tx5_nonce,

    //utxo1 (null utxo)
    nullifer0,
    nulliferWitness0,
    utxoWitness0,
    tx5_transfer_amt, //Field(0),   FIXME!!
    tx5_nonce,

    sig7, // Signature

    //private recipients
    //send to user4
    pv_user4_pk,
    tx7_transfer_amt,
    tx7_recipientNonce0,
    newPrivateWitness0,

    //refund to self as new utxo
    pv_user3_pk,
    tx5_transfer_amt.sub(tx7_transfer_amt),
    tx7_recipientNonce1,
    newPrivateWitness1
  );
});

await txn7.prove();
await txn7.sign([senderKey]).send();

await merkleListener.fetchEvents();

//update off-chain tree
const t7_sender_update_data_offline = privateLeaf(
  pv_user3_pk,
  pv_user3_bal.sub(tx7_transfer_amt),
  pv_user3_blindNonce
);
const t7_recipient_update_data_offline = privateLeaf(
  pv_user4_pk,
  tx7_transfer_amt,
  pv_user4_blindNonce
);
privateTree.setLeaf(prv_user3_idx, t7_sender_update_data_offline);
privateTree.setLeaf(prv_user4_idx, t7_recipient_update_data_offline);

pv_user3_bal = pv_user3_bal.sub(tx7_transfer_amt);
pv_user4_bal = tx7_transfer_amt;

const privateTreeRoot7 = zkAppInstance.privateTreeRoot.get();
console.log('private tree root (offline): ', privateTree.getRoot().toString());
console.log('private tree root after txn7:', privateTreeRoot7.toString());

// ----------------------- tx8 private->public transfer -----------------------------

console.log('--- tx8 private to public transfer ---');

const tx8_transfer_amt = Field(2);
const senderWitness8 = new MerkleWitness32(
  privateTree.getWitness(prv_user4_idx)
);
const recipientWitness8 = new MerkleWitness32(publicTree.getWitness(user1_idx));

const txn8 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.transferToPublic(
    //sender
    senderWitness8,
    pv_user4_pk,
    pv_user4_bal,
    pv_user4_blindNonce,
    //sig, //signature TODO

    //recipient
    recipientWitness8,
    user1_pk,
    user1_bal,

    //amount
    tx8_transfer_amt
  );
});

await txn8.prove();
await txn8.sign([senderKey]).send();

await merkleListener.fetchEvents();

//update off-chain tree
const t8_sender_update_data_offline = privateLeaf(
  pv_user4_pk,
  pv_user4_bal.sub(tx8_transfer_amt),
  pv_user4_blindNonce
);
const t8_recipient_update_data_offline = publicLeaf(
  user1_pk,
  user1_bal.add(tx8_transfer_amt)
);
privateTree.setLeaf(prv_user4_idx, t8_sender_update_data_offline);
publicTree.setLeaf(user1_idx, t8_recipient_update_data_offline);

pv_user4_bal = pv_user4_bal.sub(tx8_transfer_amt);
user1_bal = user1_bal.add(tx8_transfer_amt);

const privateTreeRoot8 = zkAppInstance.privateTreeRoot.get();
console.log('private tree root (offline): ', privateTree.getRoot().toString());
console.log('private tree root after txn8:', privateTreeRoot8.toString());

const publicTreeRoot8 = zkAppInstance.publicTreeRoot.get();
console.log('public tree root (offline): ', publicTree.getRoot().toString());
console.log('public tree root after txn8:', publicTreeRoot8.toString());

// ----------------------------------------------------
console.log('--- Shutting down ---');
merkleListener.shutdown();
await shutdown();
