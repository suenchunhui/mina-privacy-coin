import {
    Field,
    SmartContract,
    state,
    State,
    method,
    MerkleWitness,
    PublicKey,
    Signature,
    Nullifier,
    MerkleMapWitness,
    Provable,
  } from 'o1js';
  import { Coin } from './Coin.js';
  
  class MerkleWitness32 extends MerkleWitness(32) {}
  
  export class Sales extends SmartContract {
    @state(PublicKey) salesPool = State<PublicKey>();
    @state(PublicKey) coinPk = State<PublicKey>();
    @state(Field) price = State<Field>();
    @state(Field) count = State<Field>();

    events = {
        'sales': Field,
    }
    
    @method initState(
      salesPool: PublicKey,
      coinPk: PublicKey,
      price: Field
    ) {
      this.salesPool.set(salesPool);
      this.coinPk.set(coinPk);
      this.price.set(price);
    }
  
    init() {
      super.init();
    }
  
    //private->private transfer
    @method buy(
      //private sender
      sender: PublicKey,
  
      //utxo tuples (nullifier, amount, nonce) to be nullifier
      nullifer0: Nullifier,
      nulliferWitness0: MerkleMapWitness,
      utxoWitness0: MerkleWitness32,
      senderAmount0: Field,
      senderNonce0: Field,
  
      nullifer1: Nullifier,
      nulliferWitness1: MerkleMapWitness,
      utxoWitness1: MerkleWitness32,
      senderAmount1: Field,
      senderNonce1: Field,
  
      //sender signature
      senderSig: Signature,
  
      //private recipients
      recipientNonce0: Field,
      newPrivateWitness0: MerkleWitness32,
  
      recipient1: PublicKey,
      recipientNonce1: Field,
      newPrivateWitness1: MerkleWitness32
    ) {
      //assert state
      const salesPool = this.salesPool.getAndAssertEquals();
      const price = this.price.getAndAssertEquals();
      const count = this.count.getAndAssertEquals();

      //assert sufficient amount
      const inputBal = Provable.if(utxoWitness0.equals(utxoWitness1), senderAmount0, senderAmount0.add(senderAmount1));
      inputBal.assertGreaterThanOrEqual(price);
      const remainder = inputBal.sub(price);

      //coin contract
      const coinPk = this.coinPk.getAndAssertEquals();
      const coin = new Coin(coinPk);

      coin.transferPrivateToPrivate(
        sender,
        nullifer0,
        nulliferWitness0,
        utxoWitness0,
        senderAmount0,
        senderNonce0,    
        nullifer1,
        nulliferWitness1,
        utxoWitness1,
        senderAmount1,
        senderNonce1,
        senderSig,
        salesPool, //recipient0
        price,     //recipientAmount0
        recipientNonce0,
        newPrivateWitness0,
        recipient1,
        remainder, //recipientAmount1
        recipientNonce1,
        newPrivateWitness1
      );      
  
      //set new index
      this.count.set(count.add(1));

      //emit event
      this.emitEvent('sales', Field(1));
    }
  
  }
  