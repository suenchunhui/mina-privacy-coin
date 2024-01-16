import {
  Field,
  SmartContract,
  state,
  State,
  method,
  MerkleTree,
  MerkleMap,
  MerkleWitness,
  PublicKey,
  Bool,
  Poseidon,
  Signature,
  Nullifier,
  MerkleMapWitness,
  Provable,
} from 'o1js';

// more efficient version of `maybeSwapBad` which reuses an intermediate variable
function maybeSwap(b: Bool, x: Field, y: Field): [Field, Field] {
  let m = b.toField().mul(x.sub(y)); // b*(x - y)
  const x_ = y.add(m); // y + b*(x - y)
  const y_ = x.sub(m); // x - b*(x - y) = x + b*(y - x)
  return [x_, y_];
}

function nextHash(isLeft: Bool, hash: Field, nextHash: Field) {
  const [left1, right1] = maybeSwap(isLeft, hash, nextHash);
  return Poseidon.hash([left1, right1]);
}

function calculateIndexAtHeight(witness: MerkleWitness32, h: number): Field {
  let powerOfTwo = Field(1);
  let index = Field(0);
  let n = witness.height();

  for (let i = h; i < n - 1; i++) {
    index = Provable.if(witness.isLeft[i], index, index.add(powerOfTwo));
    powerOfTwo = powerOfTwo.mul(2);
  }
  return index;
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

  //  let idx1 = witness1.calculateIndex();
  //  let idx2 = witness2.calculateIndex();

  for (let i = 1; i <= n - 1; ++i) {
    let idx1_next = calculateIndexAtHeight(witness1, i);
    let idx2_next = calculateIndexAtHeight(witness2, i);
    let merged_hash = Poseidon.hash([hash1, hash2]); //nextHash(idx1.lessThanOrEqual(idx2), hash1, hash2);

    if (i == n - 1) return merged_hash;

    hash1 = Provable.if(
      idx1_next.equals(idx2_next),
      Provable.if(witness1.isLeft[i], merged_hash, witness1.path[i]),
      nextHash(witness1.isLeft[i - 1], hash1, witness1.path[i - 1])
    );
    hash2 = Provable.if(
      idx1_next.equals(idx2_next),
      Provable.if(witness1.isLeft[i], witness1.path[i], merged_hash),
      nextHash(witness2.isLeft[i - 1], hash2, witness2.path[i - 1])
    );

    //    idx1 = idx1_next;
    //    idx2 = idx2_next;
  }

  return hash1;
}

class MerkleWitness32 extends MerkleWitness(32) {}

export class Coin extends SmartContract {
  @state(Field) publicTreeRoot = State<Field>();
  @state(Field) privateTreeRoot = State<Field>();
  @state(Field) nextPrivateIndex = State<Field>();
  @state(Field) nullifierMapRoot = State<Field>();

  events = {
    'update-public-address': PublicKey,
    'update-public-balance': Field,
    'update-public-leaf-index': Field,
    'update-private-leaf': Field,
    'update-private-leaf-index': Field,
    'update-nullifier-leaf-index': Field,
  };

  init() {
    super.init();

    const emptyTree = new MerkleTree(32);
    const emptyMap = new MerkleMap();
    this.publicTreeRoot.set(emptyTree.getRoot());
    this.privateTreeRoot.set(emptyTree.getRoot());
    this.nextPrivateIndex.set(Field(0));
    this.nullifierMapRoot.set(emptyMap.getRoot());
  }

  //internal functions ---

  //public node (account & balance)
  publicLeaf(recipient: PublicKey, amount: Field): Field {
    const pkfields = recipient.toFields();
    return Poseidon.hash([pkfields[0], pkfields[1], amount]);
  }

  //private node (blind utxo)
  privateUTXOLeaf(recipient: PublicKey, amount: Field, nonce: Field): Field {
    const pkfields = recipient.toFields();
    return Poseidon.hash([pkfields[0], pkfields[1], amount, nonce]);
  }

  //nullifier key (nullifier map for utxo)
  nullifierKey(nullifier: Nullifier, utxoIndex: Field): Field {
    return Poseidon.hash([
      nullifier.public.nullifier.x,
      nullifier.public.nullifier.y,
      utxoIndex,
    ]);
  }

  //payment for minting
  @method mint(
    leafWitness: MerkleWitness32,
    emptyLeaf: Bool,
    recipient: PublicKey,
    currentBal: Field,
    incrementAmount: Field
  ) {
    const rootBefore = this.publicTreeRoot.get();
    this.publicTreeRoot.assertEquals(rootBefore);

    //leaf node is Field(0) if uninitialized, otherwise, use publicLeaf() to construct a hash of the node
    const leafBeforeData = Provable.if(
      emptyLeaf,
      Field(0),
      this.publicLeaf(recipient, currentBal)
    );

    // check the initial state matches what we expect
    rootBefore.assertEquals(leafWitness.calculateRoot(leafBeforeData));

    //new balance
    const newBalance = Provable.if(
      emptyLeaf,
      incrementAmount,
      currentBal.add(incrementAmount)
    );

    // compute the root after incrementing
    const leafAfter = this.publicLeaf(recipient, newBalance);
    const rootAfter = leafWitness.calculateRoot(leafAfter);

    // set the new root
    this.publicTreeRoot.set(rootAfter);

    //emit events
    this.emitEvent('update-public-leaf-index', leafWitness.calculateIndex());
    this.emitEvent('update-public-address', recipient);
    this.emitEvent('update-public-balance', newBalance);
  }

  //public-public transfer
  @method transfer(
    //public sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    senderSig: Signature,

    //public recipient
    emptyRecipientLeaf: Bool,
    recipientWitness: MerkleWitness32,
    recipient: PublicKey,
    recipientBal: Field,

    //amount
    amount: Field
  ) {
    //assert public root
    const publicRoot = this.publicTreeRoot.get();
    this.publicTreeRoot.assertEquals(publicRoot);

    //assert sender witness
    const senderRootBefore = senderWitness.calculateRoot(
      this.publicLeaf(sender, senderBal)
    );
    senderRootBefore.assertEquals(publicRoot);

    //assert sender signature
    senderSig.verify(sender, [publicRoot, amount]).assertTrue();

    //assert recipient witness
    //leaf node is Field(0) if uninitialized, otherwise, use publicLeaf() to construct a hash of the node
    const leafDataBefore = Provable.if(
      emptyRecipientLeaf,
      Field(0),
      this.publicLeaf(recipient, recipientBal)
    );
    const recipientRootBefore = recipientWitness.calculateRoot(leafDataBefore);
    recipientRootBefore.assertEquals(publicRoot);

    // //assert sufficient balance
    amount.assertLessThanOrEqual(senderBal);

    //calculate new sender leaf
    const newSenderBal = senderBal.sub(amount);
    const leafData1 = this.publicLeaf(sender, newSenderBal);

    //calculate new recipient leaf
    const newRecipientBal = Provable.if(
      emptyRecipientLeaf,
      amount,
      recipientBal.add(amount)
    );
    const leafData2 = this.publicLeaf(recipient, newRecipientBal);

    //calculate new root
    const rootAfter = calculateUpdate2Roots(
      senderWitness,
      recipientWitness,
      leafData1,
      leafData2
    );

    // set the new root
    this.publicTreeRoot.set(rootAfter);

    //emit events for sender leaf
    this.emitEvent('update-public-leaf-index', senderWitness.calculateIndex());
    this.emitEvent('update-public-address', sender);
    this.emitEvent('update-public-balance', newSenderBal);

    //emit events for recipient leaf
    this.emitEvent(
      'update-public-leaf-index',
      recipientWitness.calculateIndex()
    );
    this.emitEvent('update-public-address', recipient);
    this.emitEvent('update-public-balance', newRecipientBal);
  }

  //public->private transfer
  @method transferToPrivate(
    //public sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    senderSig: Signature,

    //private recipient
    recipient: PublicKey,
    nonce: Field,
    newPrivateWitness: MerkleWitness32,

    //amount
    amount: Field
  ) {
    //assert public root
    const publicRoot = this.publicTreeRoot.getAndAssertEquals();

    //assert private root
    const privateRoot = this.privateTreeRoot.getAndAssertEquals();

    //assert sender witness
    const senderRootBefore = senderWitness.calculateRoot(
      this.publicLeaf(sender, senderBal)
    );
    senderRootBefore.assertEquals(publicRoot);

    //assert private tree
    const currIndex = this.nextPrivateIndex.getAndAssertEquals();
    const privateRootBefore = newPrivateWitness.calculateRoot(Field(0));
    privateRoot.assertEquals(privateRootBefore);
    this.nextPrivateIndex.assertEquals(newPrivateWitness.calculateIndex());
    currIndex.assertEquals(newPrivateWitness.calculateIndex());

    //assert sender signature
    senderSig.verify(sender, [publicRoot, privateRoot, amount]).assertTrue();

    //assert sender sufficient balance
    amount.assertLessThanOrEqual(senderBal);

    //calculate new sender leaf
    const newSenderBal = senderBal.sub(amount);
    const newPublicLeaf = this.publicLeaf(sender, newSenderBal);

    //calculate new utxo leaf and index
    const utxoLeaf = this.privateUTXOLeaf(recipient, amount, nonce);
    const newIndex = currIndex.add(1);

    //calculate new public root
    const publicRootAfter = senderWitness.calculateRoot(newPublicLeaf);

    // set the new public root
    this.publicTreeRoot.set(publicRootAfter);

    //calculate new private root
    const privateRootAfter = newPrivateWitness.calculateRoot(utxoLeaf);

    // set the new private root and index
    this.privateTreeRoot.set(privateRootAfter);
    this.nextPrivateIndex.set(newIndex);

    //emit events for sender leaf (in-situ replacement)
    this.emitEvent('update-public-leaf-index', senderWitness.calculateIndex());
    this.emitEvent('update-public-address', sender);
    this.emitEvent('update-public-balance', newSenderBal);

    //emit events for recipient leaf (append to utxo tree)
    this.emitEvent('update-private-leaf-index', currIndex);
    this.emitEvent('update-private-leaf', utxoLeaf);
  }

  verifyNullifier = (
    sender: PublicKey,
    nullifer: Nullifier,
    nulliferWitness: MerkleMapWitness,
    utxoWitness: MerkleWitness32,
    senderAmount: Field,
    senderNonce: Field
  ) => {
    // verify the nullifier leaf at `utxoIndex` location is empty(zero)
    let utxoIndex = utxoWitness.calculateIndex();
    let [impliedNullRoot, impliedNullIndex] = nulliferWitness.computeRootAndKey(
      Field(0)
    );
    this.nullifierMapRoot.assertEquals(impliedNullRoot);
    let calculatedKey = this.nullifierKey(nullifer, utxoIndex);
    impliedNullIndex.assertEquals(calculatedKey);

    // verify nullifier & PK
    let utxoLeaf = this.privateUTXOLeaf(sender, senderAmount, senderNonce);
    nullifer.verify([utxoLeaf]);
    sender.assertEquals(nullifer.getPublicKey());

    // verify utxo leaf
    this.privateTreeRoot.assertEquals(utxoWitness.calculateRoot(utxoLeaf));

    //update nullfier map by setting leaf to Field(1)
    let [newNullRoot] = nulliferWitness.computeRootAndKey(Field(1));
    this.nullifierMapRoot.set(newNullRoot);

    //emit nullifier events
    this.emitEvent('update-nullifier-leaf-index', calculatedKey);
  };

  verifyPrivateWitness = (
    newIndex: Field,
    privateRoot: Field,
    recipient: PublicKey,
    recipientAmount: Field,
    recipientNonce: Field,
    newPrivateWitness: MerkleWitness32
  ): Field => {
    //verify newPrivateWitness & index
    privateRoot.assertEquals(newPrivateWitness.calculateRoot(Field(0)));
    newIndex.assertEquals(newPrivateWitness.calculateIndex());

    //calculate new utxo leaf and index
    const utxoLeaf = this.privateUTXOLeaf(
      recipient,
      recipientAmount,
      recipientNonce
    );

    return utxoLeaf;
  };

  //private->private transfer
  @method transferPrivateToPrivate(
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
    recipient0: PublicKey,
    recipientAmount0: Field,
    recipientNonce0: Field,
    newPrivateWitness0: MerkleWitness32,

    recipient1: PublicKey,
    recipientAmount1: Field,
    recipientNonce1: Field,
    newPrivateWitness1: MerkleWitness32
  ) {
    //assert private root
    const privateRoot = this.privateTreeRoot.get();
    this.privateTreeRoot.assertEquals(privateRoot);

    //assert nullifier root
    //let nullifierRoot = this.nullifierMapRoot.getAndAssertEquals();   //unnecessary, not used

    //assert nullifiers & sender utxo
    this.verifyNullifier(
      sender,
      nullifer0,
      nulliferWitness0,
      utxoWitness0,
      senderAmount0,
      senderNonce0
    );

    //TODO to conditionally skip sender1
    this.verifyNullifier(
      sender,
      nullifer1,
      nulliferWitness1,
      utxoWitness1,
      senderAmount1,
      senderNonce1
    );

    //if utxo0 == utxo1, only count the amount once,
    //otherwise sum nullifier0 and nullifier1
    const amount = Provable.if(
      nulliferWitness0.equals(nulliferWitness1),
      senderAmount0,
      senderAmount0.add(senderAmount1)
    );

    //assert sender signature
    senderSig
      .verify(sender, [privateRoot, senderAmount0, senderAmount1])
      .assertTrue();

    //check new UTXOs
    let privateRootAfter = privateRoot;
    let newIndex = this.nextPrivateIndex.getAndAssertEquals();

    //assert sum of input = sum of output
    amount.assertEquals(recipientAmount0.add(recipientAmount1));

    //verify private & increment (0)
    let utxoLeaf = this.verifyPrivateWitness(
      newIndex,
      privateRootAfter,
      recipient0,
      recipientAmount0,
      recipientNonce0,
      newPrivateWitness0
    );
    privateRootAfter = newPrivateWitness0.calculateRoot(utxoLeaf);

    //emit events for recipient leaf1 (append to utxo tree)
    this.emitEvent('update-private-leaf-index', newIndex);
    this.emitEvent('update-private-leaf', utxoLeaf);

    //increment index
    newIndex = newIndex.add(1);

    //verify private & increment (1)
    utxoLeaf = this.verifyPrivateWitness(
      newIndex,
      privateRootAfter,
      recipient1,
      recipientAmount1,
      recipientNonce1,
      newPrivateWitness1
    );
    privateRootAfter = newPrivateWitness1.calculateRoot(utxoLeaf);

    // set the new private root
    this.privateTreeRoot.set(privateRootAfter);

    //emit events for recipient leaf1 (append to utxo tree)
    this.emitEvent('update-private-leaf-index', newIndex);
    this.emitEvent('update-private-leaf', utxoLeaf);

    //set new index
    this.nextPrivateIndex.set(newIndex.add(1));
  }

  //private->public transfer
  @method transferPrivateToPublic(
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

    //private recipient
    recipient0: PublicKey,
    recipientAmount0: Field,
    recipientNonce0: Field,
    newPrivateWitness0: MerkleWitness32,

    //public recipient
    emptyRecipientLeaf: Bool,
    recipientWitness: MerkleWitness32,
    recipient: PublicKey,
    recipientBal: Field,
    publicAmount: Field
  ) {
    // //assert private root
    const privateRoot = this.privateTreeRoot.get();
    this.privateTreeRoot.assertEquals(privateRoot);

    //assert nullifier root
    //let nullifierRoot = this.nullifierMapRoot.getAndAssertEquals();   //unnecessary, not used

    //assert nullifiers & sender utxo
    this.verifyNullifier(
      sender,
      nullifer0,
      nulliferWitness0,
      utxoWitness0,
      senderAmount0,
      senderNonce0
    );

    //TODO to conditionally skip sender1
    this.verifyNullifier(
      sender,
      nullifer1,
      nulliferWitness1,
      utxoWitness1,
      senderAmount1,
      senderNonce1
    );

    //if utxo0 == utxo1, only count the amount once,
    //otherwise sum nullifier0 and nullifier1
    const amount = Provable.if(
      nulliferWitness0.equals(nulliferWitness1),
      senderAmount0,
      senderAmount0.add(senderAmount1)
    );

    //assert sender signature
    senderSig
      .verify(sender, [privateRoot, senderAmount0, senderAmount1])
      .assertTrue();

    //check new UTXOs
    let privateRootAfter = privateRoot;
    let newIndex = this.nextPrivateIndex.getAndAssertEquals();

    //assert sum of input = sum of output
    amount.assertEquals(recipientAmount0.add(publicAmount));

    //verify private & increment (0)
    let utxoLeaf = this.verifyPrivateWitness(
      newIndex,
      privateRootAfter,
      recipient0,
      recipientAmount0,
      recipientNonce0,
      newPrivateWitness0
    );
    privateRootAfter = newPrivateWitness0.calculateRoot(utxoLeaf);

    //emit events for recipient leaf1 (append to utxo tree)
    this.emitEvent('update-private-leaf-index', newIndex);
    this.emitEvent('update-private-leaf', utxoLeaf);

    // set the new private root
    this.privateTreeRoot.set(privateRootAfter);

    //emit events for recipient leaf1 (append to utxo tree)
    this.emitEvent('update-private-leaf-index', newIndex);
    this.emitEvent('update-private-leaf', utxoLeaf);

    //set new index
    this.nextPrivateIndex.set(newIndex.add(1));

    //assert public root
    const publicRoot = this.publicTreeRoot.get();
    this.publicTreeRoot.assertEquals(publicRoot);

    //assert recipient witness
    //leaf node is Field(0) if uninitialized, otherwise, use publicLeaf() to construct a hash of the node
    const leafDataBefore = Provable.if(
      emptyRecipientLeaf,
      Field(0),
      this.publicLeaf(recipient, recipientBal)
    );
    const recipientRootBefore = recipientWitness.calculateRoot(leafDataBefore);
    recipientRootBefore.assertEquals(publicRoot);

    //calculate new recipient leaf
    const newRecipientBal = Provable.if(
      emptyRecipientLeaf,
      publicAmount,
      recipientBal.add(publicAmount)
    );
    const leafData2 = this.publicLeaf(recipient, newRecipientBal);

    //calculate new root
    const rootAfter = recipientWitness.calculateRoot(leafData2);

    // set the new root
    this.publicTreeRoot.set(rootAfter);

    //emit events for recipient leaf
    this.emitEvent(
      'update-public-leaf-index',
      recipientWitness.calculateIndex()
    );
    this.emitEvent('update-public-address', recipient);
    this.emitEvent('update-public-balance', newRecipientBal);
  }
}
