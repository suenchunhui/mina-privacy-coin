import 'dotenv/config';
import { Coin } from './Coin.js';
import { Sales } from './Sales.js';
import {MerkleListener, MerkleListenerLib} from './server.js';
import {
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
  Nullifier,
  Signature,
} from 'o1js';
import { assert } from 'chai';

// --- additional helper functions ---
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

function nullifierKey(nullifier: Nullifier, utxoIndex: Field): Field {
  return Poseidon.hash([
    nullifier.public.nullifier.x,
    nullifier.public.nullifier.y,
    utxoIndex,
  ]);
}

describe('End-to-end test', async () => {
  //test setup
  const transactionFee = 100_000_000;
  const api_port = 30001;
  let senderKey: PrivateKey, senderAccount: PublicKey;
  let Local;
  const useProof = false;
  Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
  Mina.setActiveInstance(Local);
  console.log('  Using local network');

  senderKey = Local.testAccounts[1].privateKey;
  senderAccount = Local.testAccounts[1].publicKey;

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

  // --- init users ---
  // Create a public/private key pair. For users
  //public users
  const user1_priv = PrivateKey.random();
  const user1_pk = user1_priv.toPublicKey();
  
  let user1_bal = Field(0); //mint_amt.sub(tx3_transfer_amt);
  let pv_user3_bal = Field(0);

  //private users
  const pv_user3_priv = PrivateKey.random();
  const pv_user3_pk = pv_user3_priv.toPublicKey();
  
  //init contract
  let coinAddress: PublicKey;
  let salesAddress: PublicKey;
  let coinInstance: Coin;
  let salesInstance: Sales;

  // Deployer account
  let deployerAccount: PublicKey, deployerKey: PrivateKey;
  deployerKey = Local.testAccounts[0].privateKey;
  deployerAccount = Local.testAccounts[0].publicKey;

  //Contract instances
  const coinPrivateKey = PrivateKey.random();
  coinAddress = coinPrivateKey.toPublicKey();
  coinInstance = new Coin(coinAddress);

  const salesPrivateKey = PrivateKey.random();
  salesAddress = salesPrivateKey.toPublicKey();
  salesInstance = new Sales(salesAddress);

  //Global params
  const salesPoolPrivateKey = PrivateKey.random();
  const salesPool = salesPoolPrivateKey.toPublicKey();
  const price = Field(2);


  // -------------------- deploy an instance of Coin at coinAddress ----------------------

  const merkleListener = new MerkleListener(coinInstance, height, api_port);
  await merkleListener.start();
  const listener = new MerkleListenerLib("localhost", api_port);

  it('Coin contract deploys with correct merkle roots', async () => {
    const deployTxn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      coinInstance.deploy();
      coinInstance.initState(
        initialPublicRoot,
        initialPrivateRoot,
        initialNullifierRoot
      );
    });
    await deployTxn.prove();
    await deployTxn.sign([deployerKey, coinPrivateKey]).send();

    assert.equal(
      initialPublicRoot.toString(),
      coinInstance.publicTreeRoot.get().toString()
    );
  });

  it('Sales contract deploys', async () => {
    const deployTxn2 = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      salesInstance.deploy();
      salesInstance.initState(
        salesPool,
        coinAddress,
        price
      );
    });
    await deployTxn2.prove();
    await deployTxn2.sign([deployerKey, salesPrivateKey]).send();
  });

  // ----------------------- tx2 public mint -----------------------------

  const user1_idx = BigInt(2);
  const mint_amt = Field(10);

  it('minting of public tokens', async () => {
    //update off-chain tree
    const tx2_leafWitness = new MerkleWitness32(publicTree.getWitness(user1_idx));
    const txn2 = await Mina.transaction(senderAccount, () => {
      coinInstance.mint(
        tx2_leafWitness,
        Bool(true), //emptyLeaf
        user1_pk, //recipient
        Field(0), //currentBal
        mint_amt //amount
      );
    });
    await txn2.prove();
    await txn2.sign([senderKey]).send();

    //events
    await merkleListener.fetchEvents();

    //offline merkle tree update
    publicTree.setLeaf(user1_idx, publicLeaf(user1_pk, mint_amt));
     
    //compare merkle root
    assert.equal(
      publicTree.getRoot().toString(),
      coinInstance.publicTreeRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      publicTree.getRoot().toString(),
      await listener.getPublicRoot()
    );

    user1_bal = user1_bal.add(mint_amt);
  });

  // ----------------------- tx5 public->private transfer -----------------------------

  const tx5_transfer_amt = Field(5);
  const tx5_nonce = Field(Math.floor(Math.random() * 100000)); //TODO not-crypto secure random

  it('public to private token transfer', async () => {    
    const tx5_senderWitness = new MerkleWitness32(publicTree.getWitness(user1_idx));
    let tx5_utxo_index = 0n;
    let tx5_utxoWitness = new MerkleWitness32(privateTree.getWitness(tx5_utxo_index));
    const sig5 = Signature.create(user1_priv, [
      publicTree.getRoot(),
      privateTree.getRoot(),
      tx5_transfer_amt,
    ]);
  
    const txn5 = await Mina.transaction(senderAccount, () => {
      coinInstance.transferToPrivate(
        //sender
        tx5_senderWitness,
        user1_pk,
        user1_bal,
        sig5, //signature

        //recipient
        pv_user3_pk, //recipient
        tx5_nonce, //nonce
        tx5_utxoWitness, //newPrivateWitness

        //amount
        tx5_transfer_amt
      );
    });

    await txn5.prove();
    await txn5.sign([senderKey]).send();

    await merkleListener.fetchEvents();

    //update off-chain tree
    const t5_sender_update_data_offline = publicLeaf(
      user1_pk,
      user1_bal.sub(tx5_transfer_amt)
    );
    publicTree.setLeaf(user1_idx, t5_sender_update_data_offline);
    const tx5_recipient_update_data_offline = privateUTXOLeaf(
      pv_user3_pk,
      tx5_transfer_amt,
      tx5_nonce
    );
    privateTree.setLeaf(tx5_utxo_index, tx5_recipient_update_data_offline);

    user1_bal = user1_bal.sub(tx5_transfer_amt);
    pv_user3_bal = tx5_transfer_amt;

    //check computed public and private tree
    assert.equal(
      publicTree.getRoot().toString(),
      coinInstance.publicTreeRoot.get().toString()
    );
    assert.equal(
      privateTree.getRoot().toString(),
      coinInstance.privateTreeRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      publicTree.getRoot().toString(),
      await listener.getPublicRoot()
    );
    assert.equal(
      privateTree.getRoot().toString(),
      await listener.getPrivateRoot()
    );

  });

  // ----------------------- tx7 private sales -----------------------------

  const tx7_recipientNonce0 = Field(Math.floor(Math.random() * 100000));

  it('private sales to contract call', async () => {
    const tx7_utxo0 = privateUTXOLeaf(pv_user3_pk, tx5_transfer_amt, tx5_nonce);
    const tx7_nullifer0 = Nullifier.fromJSON(
      Nullifier.createTestNullifier([tx7_utxo0], pv_user3_priv)
    );
  
    const tx7_utxoIndex = Field(0);
  
    const tx7_calculatedKey = nullifierKey(tx7_nullifer0, tx7_utxoIndex);
    const tx7_nulliferWitness0 = nullifierTree.getWitness(tx7_calculatedKey);
  
    const tx7_sig = Signature.create(pv_user3_priv, [
      privateTree.getRoot(),
      tx5_transfer_amt,
      tx5_transfer_amt,
    ]);
  
    const tx7_utxoWitness0 = new MerkleWitness32(privateTree.getWitness(0n));
  
    const tx7_newPrivateWitness0 = new MerkleWitness32(
      privateTree.getWitness(1n)
    );
    const tx7_recipient_leaf0 = privateUTXOLeaf(
      salesPool,
      price,
      tx7_recipientNonce0
    );
    privateTree.setLeaf(1n, tx7_recipient_leaf0);
    let tx7_newPrivateWitness1 = new MerkleWitness32(privateTree.getWitness(2n));
    let tx7_recipientNonce1 = Field(Math.floor(Math.random() * 100000));
  
    const txn7 = await Mina.transaction(senderAccount, () => {
      salesInstance.buy(
        //sender
        pv_user3_pk,

        //utxo0 to spend
        tx7_nullifer0,
        tx7_nulliferWitness0,
        tx7_utxoWitness0,
        tx5_transfer_amt,
        tx5_nonce,

        //utxo1 (repeat)
        tx7_nullifer0,
        tx7_nulliferWitness0,
        tx7_utxoWitness0,
        tx5_transfer_amt,
        tx5_nonce,

        tx7_sig, // Signature

        //private sales recipients
        tx7_recipientNonce0,
        tx7_newPrivateWitness0,

        //refund to self as new utxo
        pv_user3_pk,
        tx7_recipientNonce1,
        tx7_newPrivateWitness1
      );
    });

    await txn7.prove();
    await txn7.sign([senderKey]).send();

    await merkleListener.fetchEvents();

    //Update private tree
    const tx7_recipient_update1 = privateUTXOLeaf(
      pv_user3_pk,
      tx5_transfer_amt.sub(price),
      tx7_recipientNonce1
    );
    privateTree.setLeaf(2n, tx7_recipient_update1);

    assert.equal(
      privateTree.getRoot().toString(),
      coinInstance.privateTreeRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      privateTree.getRoot().toString(),
      await listener.getPrivateRoot()
    );

    //Update nullifier tree
    nullifierTree.set(tx7_calculatedKey, Field(1));

    assert.equal(
      nullifierTree.getRoot().toString(),
      coinInstance.nullifierMapRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      nullifierTree.getRoot().toString(),
      await listener.getNullifierRoot()
    );

    //close merkle listener
    merkleListener.shutdown();
  });

});
