import { Coin } from './Coin.js';
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
} from 'snarkyjs';

// await isReady;
console.log('SnarkyJS loaded');
const useProof = false;
const Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
Mina.setActiveInstance(Local);
const { privateKey: deployerKey, publicKey: deployerAccount } =
  Local.testAccounts[0];
const { privateKey: senderKey, publicKey: senderAccount } =
  Local.testAccounts[1];

// --- additional functions ---
function publicLeaf(recipient: PublicKey, amount: Field): Field {
  const pkfields = recipient.toFields();
  return Poseidon.hash([pkfields[0], pkfields[1], amount]);
}

function maybeSwap(b: Bool, x: Field, y: Field): [Field, Field] {
  // if(b.equals(Bool(true))){
  //   return [x, y];
  // }else{
  //   return [y, x];
  // }
  let m = b.toField().mul(x.sub(y)); // b*(x - y)
  const x_ = y.add(m); // y + b*(x - y)
  const y_ = x.sub(m); // x - b*(x - y) = x + b*(y - x)
  return [x_, y_];
}

function nextHash(isLeft: Bool, hash: Field, nextHash: Field) {
  const [left1, right1] = maybeSwap(isLeft, hash, nextHash);
  return Poseidon.hash([left1, right1]);
}

function calculateUpdate2Roots(
  witness1: MerkleWitness32,
  witness2: MerkleWitness32,
  leaf1: Field,
  leaf2: Field
): Field {
  let n = witness1.height();
  let hash1 = leaf1;
  let hash2 = leaf2;

  let idx1 = witness1.calculateIndex();
  let idx2 = witness2.calculateIndex();

  //  console.log('d1 ', idx1, idx2);

  for (let i = 1; i < n; ++i) {
    let idx1_next = idx1.div(Field(2));
    let idx2_next = idx2.div(Field(2));

    if (idx1_next.equals(idx2_next)) {
      hash2 = hash1 = Poseidon.hash([hash1, hash2]);
    } else {
      hash1 = nextHash(witness1.isLeft[i - 1], hash1, witness1.path[i - 1]);
      hash2 = nextHash(witness2.isLeft[i - 1], hash2, witness2.path[i - 1]);
    }
    // hash1 = Circuit.if(
    //   idx1_next.equals(idx2_next),
    //   Poseidon.hash([hash1, hash2]),  //2 branches merged   FIXME need to swap order if idx2 < idx1
    //   nextHash(witness1.isLeft[i - 1], hash1, witness1.path[i - 1])  //unmerged
    // );
    // hash2 = Circuit.if(
    //   idx1_next.equals(idx2_next),
    //   Poseidon.hash([hash1, hash2]),  //2 branches merged   FIXME need to swap order if idx2 < idx1
    //   nextHash(witness2.isLeft[i - 1], hash2, witness2.path[i - 1])  //unmerged
    // );

    idx1 = idx1_next;
    idx2 = idx2_next;
  }
  return hash1;
}

//tree defn
const height = 32;
class MerkleWitness32 extends MerkleWitness(height) {}

// --- tree init ---
const publicTree = new MerkleTree(height);
const privateTree = new MerkleTree(height);
const initialPublicRoot = publicTree.getRoot();
const initialPrivateRoot = privateTree.getRoot();

// ----------------------------------------------------
// Create a public/private key pair. The public key is your address and where you deploy the zkApp to
const zkAppPrivateKey = PrivateKey.random();
const zkAppAddress = zkAppPrivateKey.toPublicKey();

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

// --- create an instance of Coin - and deploy it to zkAppAddress ---
const zkAppInstance = new Coin(zkAppAddress);
const deployTxn = await Mina.transaction(deployerAccount, () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  zkAppInstance.deploy();
});
await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();

// -------------------- initState --------------------------------

console.log('--- deploy & init state ---');

const txn1 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.initState(initialPublicRoot, initialPrivateRoot);
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
//console.log(JSON.stringify(txn2.transaction.accountUpdates[0].body.events));
const t2_leaf_update_idx =
  txn2.transaction.accountUpdates[0].body.events.data[1][1];
const t2_leaf_update_data =
  txn2.transaction.accountUpdates[0].body.events.data[0][1];
//{"hash":"12393868177935264191752570151485810140810451890747428365625097772266920554115","data":[["0","9519604085841783924758137287891343162741228469678299686306150972915523071408"],["1","5"]]}
console.log(
  `leaf update: index: ${t2_leaf_update_idx} data: ${t2_leaf_update_data}`
);

//offline merkle tree update
const t2_leaf_update_data_offline = publicLeaf(user1_pk, mint_amt);
console.log(`leaf data computation:      ${t2_leaf_update_data_offline}`);
publicTree.setLeaf(user1_idx, publicLeaf(user1_pk, mint_amt));

//compare merkle root
const publicTreeRoot2 = zkAppInstance.publicTreeRoot.get();
console.log('tree state (offline): ', publicTree.getRoot().toString());
console.log('tree state after txn2:', publicTreeRoot2.toString());

// ----------------------- tx3 public transfer -----------------------------

console.log('--- tx3 public transfer ---');

const user2_idx = BigInt(6);
const tx3_transfer_amt = Field(7);

const senderWitness = new MerkleWitness32(publicTree.getWitness(user1_idx));
const recipientWitness = new MerkleWitness32(publicTree.getWitness(user2_idx));

const txn3 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.transfer(
    //sender
    senderWitness,
    user1_pk,
    mint_amt, //sender bal
    //sig, //signature TODO

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

/*
//events
//console.log(JSON.stringify(txn3.transaction.accountUpdates[0].body.events));
// {"hash":"8420083281727309776268175983587936228533289388643792574454353586744076044682","data":[["0","16653878613474267232387783887715849643420830000568047238359874635599369047919"],["1","6"],["0","1252359999092379544927346963835485216706032159767292630364506968907055786443"],["1","2"]]}
const t3_sender_update_idx =
  txn3.transaction.accountUpdates[0].body.events.data[3][1];
const t3_sender_update_data =
  txn3.transaction.accountUpdates[0].body.events.data[2][1];
const t3_recipient_update_idx =
  txn3.transaction.accountUpdates[0].body.events.data[1][1];
const t3_recipient_update_data =
  txn3.transaction.accountUpdates[0].body.events.data[0][1];

//update off-chain tree
const t3_sender_update_data_offline = publicLeaf(
  user1_pk,
  mint_amt.sub(tx3_transfer_amt)
);
const t3_recipient_update_data_offline = publicLeaf(user2_pk, tx3_transfer_amt);

console.log(
  `sender update:    index: ${t3_sender_update_idx} data: ${t3_sender_update_data}`
);
console.log(
  `sender data computation:         ${t3_sender_update_data_offline}`
);

console.log(
  `recipient update: index: ${t3_recipient_update_idx} data: ${t3_recipient_update_data}`
);
console.log(
  `recipient data computation:      ${t3_recipient_update_data_offline}`
);

publicTree.setLeaf(user1_idx, t3_sender_update_data_offline);
publicTree.setLeaf(user2_idx, t3_recipient_update_data_offline);

//compare merkle root
const newRoot3 = calculateUpdate2Roots(
  senderWitness,
  recipientWitness,
  t3_sender_update_data_offline,
  t3_recipient_update_data_offline
);
// console.log(senderWitness.calculateIndex().toString());
// console.log(recipientWitness.calculateIndex().toString());
// console.log(newRoot3.toString());
*/
const publicTreeRoot3 = zkAppInstance.publicTreeRoot.get();
console.log('tree root (offline): ', publicTree.getRoot().toString());
console.log('tree root after txn3:', publicTreeRoot3.toString());

let user1_bal = mint_amt.sub(tx3_transfer_amt);
let user2_bal = Field(tx3_transfer_amt);

// try {
//   const txn2 = await Mina.transaction(senderAccount, () => {
//     zkAppInstance.update(Field(75));
//   });
//   await txn2.prove();
//   await txn2.sign([senderKey]).send();
// } catch (ex: any) {
//   console.log(ex.message);
// }
// const num2 = zkAppInstance.num.get();
// console.log('state after txn2:', num2.toString());

// ----------------------- tx4 init private -----------------------------

console.log('--- tx4 init private ---');

const prv_user3_idx = BigInt(11);
let pv_user3_blindBal = Field(0);
const pv_user3_blindNonce = Field(283476); //TODO, to use random
const pv_user3_blindHash = Poseidon.hash([pv_user3_blindNonce]);

const witness4 = new MerkleWitness32(privateTree.getWitness(prv_user3_idx));

const txn4 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.initPrivate(witness4, pv_user3_pk, pv_user3_blindNonce);
});

await txn4.prove();
await txn4.sign([senderKey]).send();

// ----------------------------------------------------
console.log('Shutting down');
await shutdown();

// ----------------------------------------------------
// console.log('Shutting down')
// await shutdown();
