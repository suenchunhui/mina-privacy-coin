import 'dotenv/config';
import { Coin } from './Coin.js';
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
    console.log('  Using local network');

    senderKey = Local.testAccounts[1].privateKey;
    senderAccount = Local.testAccounts[1].publicKey;
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

  // --- init users ---
  // Create a public/private key pair. For users
  //public users
  const user1_priv = PrivateKey.random();
  const user1_pk = user1_priv.toPublicKey();
  const user2_priv = PrivateKey.random();
  const user2_pk = user2_priv.toPublicKey();

  const user2_idx = BigInt(6);

  let user1_bal = Field(0); //mint_amt.sub(tx3_transfer_amt);
  let user2_bal = Field(0); //Field(tx3_transfer_amt);
  let pv_user3_bal = Field(0);


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
    zkAppAddress = PrivateKey.fromBase58(
      process.env.ZkAppAddress
    ).toPublicKey();
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

  const merkleListener = new MerkleListener(zkAppInstance, height, api_port);
  await merkleListener.start();
  const listener = new MerkleListenerLib("localhost", api_port);

  it('contract deploys with correct merkle roots', async () => {
    const txn1 = await Mina.transaction(senderAccount, () => {
      zkAppInstance.initState(
        initialPublicRoot,
        initialPrivateRoot,
        initialNullifierRoot
      );
    });
    await txn1.prove();
    await txn1.sign([senderKey]).send();

    assert.equal(
      initialPublicRoot.toString(),
      zkAppInstance.publicTreeRoot.get().toString()
    );
  });

  // ----------------------- tx2 public mint -----------------------------

  const user1_idx = BigInt(2);
  const mint_amt = Field(10);

  it('minting of public tokens', async () => {
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

    //offline merkle tree update
    publicTree.setLeaf(user1_idx, publicLeaf(user1_pk, mint_amt));
     
    //compare merkle root
    assert.equal(
      publicTree.getRoot().toString(),
      zkAppInstance.publicTreeRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      publicTree.getRoot().toString(),
      await listener.getPublicRoot()
    );

    user1_bal = user1_bal.add(mint_amt);
  });

  // ----------------------- tx3 public transfer -----------------------------

  it('public to public token transfer', async () => {
    const tx3_transfer_amt = Field(7);
  
    const senderWitness = new MerkleWitness32(publicTree.getWitness(user1_idx));
    const recipientWitness = new MerkleWitness32(
      publicTree.getWitness(user2_idx)
    );
  
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
    const t3_recipient_update_data_offline = publicLeaf(
      user2_pk,
      tx3_transfer_amt
    );
    publicTree.setLeaf(user1_idx, t3_sender_update_data_offline);
    publicTree.setLeaf(user2_idx, t3_recipient_update_data_offline);

    //check computed public tree
    assert.equal(
      publicTree.getRoot().toString(),
      zkAppInstance.publicTreeRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      publicTree.getRoot().toString(),
      await listener.getPublicRoot()
    );    

    user1_bal = user1_bal.sub(tx3_transfer_amt);
    user2_bal = Field(tx3_transfer_amt);
  
  });

  // ----------------------- tx5 public->private transfer -----------------------------

  const tx5_transfer_amt = Field(5);
  const tx5_nonce = Field(Math.floor(Math.random() * 100000)); //TODO not-crypto secure random

  it('public to private token transfer', async () => {    
    const senderWitness5 = new MerkleWitness32(publicTree.getWitness(user2_idx));
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

    //check computed public and private tree
    assert.equal(
      publicTree.getRoot().toString(),
      zkAppInstance.publicTreeRoot.get().toString()
    );
    assert.equal(
      privateTree.getRoot().toString(),
      zkAppInstance.privateTreeRoot.get().toString()
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

  // ----------------------- tx7 private->private transfer -----------------------------

  const tx7_transfer_amt = Field(3);
  const tx7_recipientNonce0 = Field(Math.floor(Math.random() * 100000));

  it('private to private token transfer', async () => {
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
  
    const utxoWitness0 = new MerkleWitness32(privateTree.getWitness(0n));
  
    const tx7_newPrivateWitness0 = new MerkleWitness32(
      privateTree.getWitness(1n)
    );
    const tx7_recipient_leaf0 = privateUTXOLeaf(
      pv_user4_pk,
      tx7_transfer_amt,
      tx7_recipientNonce0
    );
    privateTree.setLeaf(1n, tx7_recipient_leaf0);
    let tx7_newPrivateWitness1 = new MerkleWitness32(privateTree.getWitness(2n));
    let tx7_recipientNonce1 = Field(Math.floor(Math.random() * 100000));
  
    const txn7 = await Mina.transaction(senderAccount, () => {
      zkAppInstance.transferPrivateToPrivate(
        //sender
        pv_user3_pk,

        //utxo0 to spend
        tx7_nullifer0,
        tx7_nulliferWitness0,
        utxoWitness0,
        tx5_transfer_amt,
        tx5_nonce,

        //utxo1 (repeat)
        tx7_nullifer0,
        tx7_nulliferWitness0,
        utxoWitness0,
        tx5_transfer_amt,
        tx5_nonce,

        tx7_sig, // Signature

        //private recipients
        //send to user4
        pv_user4_pk,
        tx7_transfer_amt,
        tx7_recipientNonce0,
        tx7_newPrivateWitness0,

        //refund to self as new utxo
        pv_user3_pk,
        tx5_transfer_amt.sub(tx7_transfer_amt),
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
      tx5_transfer_amt.sub(tx7_transfer_amt),
      tx7_recipientNonce1
    );
    privateTree.setLeaf(2n, tx7_recipient_update1);

    assert.equal(
      privateTree.getRoot().toString(),
      zkAppInstance.privateTreeRoot.get().toString()
    );

    // //check merkle listener
    assert.equal(
      privateTree.getRoot().toString(),
      await listener.getPrivateRoot()
    );

    //Update nullifier tree
    nullifierTree.set(tx7_calculatedKey, Field(1));

    assert.equal(
      nullifierTree.getRoot().toString(),
      zkAppInstance.nullifierMapRoot.get().toString()
    );

    //check merkle listener
    // FIXME!!!
    assert.equal(
      nullifierTree.getRoot().toString(),
      await listener.getNullifierRoot()
    );
  });

  //TODO check node js listener is correct


  // ----------------------- tx8 private->public transfer -----------------------------


  it('private to public token transfer', async () => {
    const tx8_transfer_amt = Field(1);
    const tx8_utxo0 = privateUTXOLeaf(
      pv_user4_pk,
      tx7_transfer_amt,
      tx7_recipientNonce0
    );
    const tx8_nullifer = Nullifier.fromJSON(
      Nullifier.createTestNullifier([tx8_utxo0], pv_user4_priv)
    );
    const tx8_calculatedKey = nullifierKey(tx8_nullifer, Field(1));
    const tx8_nulliferWitness = nullifierTree.getWitness(tx8_calculatedKey);
    const tx8_utxoWitness = new MerkleWitness32(privateTree.getWitness(1n));
    const tx8_sig = Signature.create(pv_user4_priv, [
      privateTree.getRoot(),
      tx7_transfer_amt,
      tx7_transfer_amt,
    ]);
  
    const tx8_recipientNonce0 = Field(Math.floor(Math.random() * 100000));
    let newPrivateWitness8_0 = new MerkleWitness32(privateTree.getWitness(3n)); //new empty slot
  
    //public recipient
    const tx8_recipientWitness = new MerkleWitness32(
      publicTree.getWitness(user2_idx)
    );
  
    const txn8 = await Mina.transaction(senderAccount, () => {
      zkAppInstance.transferPrivateToPublic(
        //sender
        pv_user4_pk,

        //utxo0 to spend
        tx8_nullifer,
        tx8_nulliferWitness,
        tx8_utxoWitness,
        tx7_transfer_amt,
        tx7_recipientNonce0,

        //utxo1 (repeat)
        tx8_nullifer,
        tx8_nulliferWitness,
        tx8_utxoWitness,
        tx7_transfer_amt,
        tx7_recipientNonce0,

        tx8_sig, // Signature

        //private recipients
        //send to user4
        pv_user4_pk,
        tx7_transfer_amt.sub(tx8_transfer_amt),
        tx8_recipientNonce0,
        newPrivateWitness8_0,

        //recipient
        Bool(false), //emptyRecipientLeaf
        tx8_recipientWitness,
        user2_pk,
        user2_bal, //recipientBal
        tx8_transfer_amt //public amount
      );
    });

    await txn8.prove();
    await txn8.sign([senderKey]).send();

    await merkleListener.fetchEvents();

    //update and check private tree
    const tx8_recipient_update1 = privateUTXOLeaf(
      pv_user4_pk,
      tx7_transfer_amt.sub(tx8_transfer_amt),
      tx8_recipientNonce0
    );
    privateTree.setLeaf(3n, tx8_recipient_update1);

    assert.equal(
      privateTree.getRoot().toString(),
      zkAppInstance.privateTreeRoot.get().toString()
    );

    //check merkle listener
    assert.equal(
      privateTree.getRoot().toString(),
      await listener.getPrivateRoot()
    );

    //Update & test nullifier tree
    nullifierTree.set(tx8_calculatedKey, Field(1));

    assert.equal(
      nullifierTree.getRoot().toString(),
      zkAppInstance.nullifierMapRoot.get().toString()
    );
    assert.equal(
      nullifierTree.getRoot().toString(),
      await listener.getNullifierRoot()
    );

    //update & test public tree
    user2_bal = user2_bal.add(tx8_transfer_amt);
    const tx8_recipient_leaf = publicLeaf(user2_pk, user2_bal);
    publicTree.setLeaf(user2_idx, tx8_recipient_leaf);

    assert.equal(
      publicTree.getRoot().toString(),
      zkAppInstance.publicTreeRoot.get().toString()
    );
    //check merkle listener
    assert.equal(
      publicTree.getRoot().toString(),
      await listener.getPublicRoot()
    );
    
    //check nextPrivateIndex
    assert.equal(
      "4",
      zkAppInstance.nextPrivateIndex.get().toString()
    );

    //close merkle listener
    merkleListener.shutdown();
  });

});
