import {
  Field,
  SmartContract,
  state,
  State,
  method,
  MerkleWitness,
  PublicKey,
  Bool,
  Circuit,
  Poseidon,
  Signature,
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
    index = Circuit.if(witness.isLeft[i], index, index.add(powerOfTwo));
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

    hash1 = Circuit.if(
      idx1_next.equals(idx2_next),
      Circuit.if(witness1.isLeft[i], merged_hash, witness1.path[i]),
      nextHash(witness1.isLeft[i - 1], hash1, witness1.path[i - 1])
    );
    hash2 = Circuit.if(
      idx1_next.equals(idx2_next),
      Circuit.if(witness1.isLeft[i], witness1.path[i], merged_hash),
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

  events = {
    'update-public-leaf': Field,
    'update-public-leaf-index': Field,
    'update-private-leaf': Field,
    'update-private-leaf-index': Field,
  };

  @method initState(initialPublicRoot: Field, initialPrivateRoot: Field) {
    this.publicTreeRoot.set(initialPublicRoot);
    this.privateTreeRoot.set(initialPrivateRoot);
  }

  init() {
    super.init();
  }

  //internal function
  publicLeaf(recipient: PublicKey, amount: Field): Field {
    const pkfields = recipient.toFields();
    return Poseidon.hash([pkfields[0], pkfields[1], amount]);
  }

  //private node (without knowing balance)
  blindPrivateLeaf(
    recipient: PublicKey,
    blindedAmount: Field,
    blindingNonceHash: Field
  ): Field {
    const pkfields = recipient.toFields();
    const left = Poseidon.hash([pkfields[0], pkfields[1], blindedAmount]);
    return Poseidon.hash([left, blindingNonceHash]);
  }

  //private node (know balance)
  privateLeaf(
    recipient: PublicKey,
    amount: Field,
    blindingNonce: Field
  ): Field {
    const pkfields = recipient.toFields();
    const left = Poseidon.hash([
      pkfields[0],
      pkfields[1],
      blindingNonce.add(amount),
    ]);
    const right = Poseidon.hash([blindingNonce]);
    return Poseidon.hash([left, right]);
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
    const leafBeforeData = Circuit.if(
      emptyLeaf,
      Field(0),
      this.publicLeaf(recipient, currentBal)
    );

    // check the initial state matches what we expect
    rootBefore.assertEquals(leafWitness.calculateRoot(leafBeforeData));

    //new balance
    const newBalance = Circuit.if(
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
    this.emitEvent('update-public-leaf', leafAfter);
  }

  //public-public transfer
  @method transfer(
    //public sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    //senderSig: Signature, //TODO
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
    //TODO

    //assert recipient witness
    //leaf node is Field(0) if uninitialized, otherwise, use publicLeaf() to construct a hash of the node
    const leafDataBefore = Circuit.if(
      emptyRecipientLeaf,
      Field(0),
      this.publicLeaf(recipient, recipientBal)
    );
    const recipientRootBefore = recipientWitness.calculateRoot(leafDataBefore);
    recipientRootBefore.assertEquals(publicRoot);

    // //assert sufficient balance
    amount.assertLessThanOrEqual(senderBal);

    //calculate new sender leaf
    const leafData1 = this.publicLeaf(sender, senderBal.sub(amount));

    //calculate new recipient leaf
    const newRecipientBal = Circuit.if(
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
    this.emitEvent('update-public-leaf', leafData1);

    //emit events for recipient leaf
    this.emitEvent(
      'update-public-leaf-index',
      recipientWitness.calculateIndex()
    );
    this.emitEvent('update-public-leaf', leafData2);
  }

  //public->private transfer
  @method initPrivate(
    //private
    witness: MerkleWitness32,
    acctPk: PublicKey,
    blindingNonce: Field
    //sig: Signature, //TODO
  ) {
    //assert private root
    const privateRoot = this.privateTreeRoot.get();
    this.privateTreeRoot.assertEquals(privateRoot);

    //assert new leaf is empty
    const rootBefore = witness.calculateRoot(Field(0));
    rootBefore.assertEquals(privateRoot);

    //TODO assert signature

    //assert new private leaf
    const newPrivateLeaf = this.privateLeaf(acctPk, Field(0), blindingNonce);
    const newPrivateRoot = witness.calculateRoot(newPrivateLeaf);

    // set the new private root
    this.privateTreeRoot.set(newPrivateRoot);

    //emit events for new leaf
    this.emitEvent('update-private-leaf-index', witness.calculateIndex());
    this.emitEvent('update-private-leaf', newPrivateLeaf);
  }

  //public->private transfer
  @method transferToPrivate(
    //public sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    //senderSig: Signature, //TODO
    //private recipient
    recipientWitness: MerkleWitness32,
    recipient: PublicKey,
    recipientBlindBal: Field,
    recipientBlindHash: Field,
    //amount
    amount: Field
  ) {
    //assert public root
    const publicRoot = this.publicTreeRoot.get();
    this.publicTreeRoot.assertEquals(publicRoot);

    //assert private root
    const privateRoot = this.privateTreeRoot.get();
    this.privateTreeRoot.assertEquals(privateRoot);

    //assert sender witness
    const senderRootBefore = senderWitness.calculateRoot(
      this.publicLeaf(sender, senderBal)
    );
    senderRootBefore.assertEquals(publicRoot);

    //assert sender signature
    //TODO

    //assert recipient leaf
    //private recipient cannot be empty
    const leafDataBefore = this.blindPrivateLeaf(
      recipient,
      recipientBlindBal,
      recipientBlindHash
    );
    const recipientRootBefore = recipientWitness.calculateRoot(leafDataBefore);
    recipientRootBefore.assertEquals(privateRoot);

    // //assert sender sufficient balance
    amount.assertLessThanOrEqual(senderBal);

    //calculate new sender leaf
    const leafData1 = this.publicLeaf(sender, senderBal.sub(amount));

    //calculate new private recipient leaf
    const leafData2 = this.blindPrivateLeaf(
      recipient,
      recipientBlindBal.add(amount),
      recipientBlindHash
    );

    //calculate new public root
    const publicRootAfter = senderWitness.calculateRoot(leafData1);

    // set the new public root
    this.publicTreeRoot.set(publicRootAfter);

    //calculate new private root
    const privateRootAfter = recipientWitness.calculateRoot(leafData2);

    // set the new private root
    this.privateTreeRoot.set(privateRootAfter);

    //emit events for sender leaf
    this.emitEvent('update-public-leaf-index', senderWitness.calculateIndex());
    this.emitEvent('update-public-leaf', leafData1);

    //emit events for recipient leaf
    this.emitEvent(
      'update-private-leaf-index',
      recipientWitness.calculateIndex()
    );
    this.emitEvent('update-private-leaf', leafData2);
  }

  //private->public transfer
  @method transferToPublic(
    //private sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    senderBlindingNonce: Field,
    //senderSig: Signature, //TODO
    //public recipient
    recipientWitness: MerkleWitness32,
    recipient: PublicKey,
    recipientBal: Field,
    //amount
    amount: Field
  ) {
    //assert public root
    const publicRoot = this.publicTreeRoot.get();
    this.publicTreeRoot.assertEquals(publicRoot);

    //assert private root
    const privateRoot = this.privateTreeRoot.get();
    this.privateTreeRoot.assertEquals(privateRoot);

    //assert sender leaf
    //private sender cannot be empty
    const leafDataBefore = this.privateLeaf(
      sender,
      senderBal,
      senderBlindingNonce
    );
    const senderRootBefore = senderWitness.calculateRoot(leafDataBefore);
    senderRootBefore.assertEquals(privateRoot);

    //assert sender signature
    //TODO

    // //assert sender sufficient balance
    amount.assertLessThanOrEqual(senderBal);

    //assert public recipient witness
    const recipientRootBefore = recipientWitness.calculateRoot(
      this.publicLeaf(recipient, recipientBal)
    );
    recipientRootBefore.assertEquals(publicRoot);

    //calculate new private sender leaf
    const leafData1 = this.privateLeaf(
      sender,
      senderBal.sub(amount),
      senderBlindingNonce
    );

    //calculate new private root
    const privateRootAfter = senderWitness.calculateRoot(leafData1);

    // set the new private root
    this.privateTreeRoot.set(privateRootAfter);

    //calculate new public recipient leaf
    const leafData2 = this.publicLeaf(recipient, recipientBal.add(amount));

    //calculate new public root
    const publicRootAfter = recipientWitness.calculateRoot(leafData2);

    // set the new public root
    this.publicTreeRoot.set(publicRootAfter);

    //emit events for public recipient leaf
    this.emitEvent(
      'update-public-leaf-index',
      recipientWitness.calculateIndex()
    );
    this.emitEvent('update-public-leaf', leafData2);

    //emit events for private sender leaf
    this.emitEvent('update-private-leaf-index', senderWitness.calculateIndex());
    this.emitEvent('update-private-leaf', leafData1);
  }

  //private->private transfer
  @method transferPrivateToPrivate(
    //private sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    senderBlindingNonce: Field,
    //senderSig: Signature, //TODO
    //private recipient
    recipientWitness: MerkleWitness32,
    recipient: PublicKey,
    recipientBlindBal: Field,
    recipientBlindHash: Field,
    //amount
    amount: Field
  ) {
    //assert private root
    const privateRoot = this.privateTreeRoot.get();
    this.privateTreeRoot.assertEquals(privateRoot);

    //assert sender leaf
    //private sender cannot be empty
    const sdLeafDataBefore = this.privateLeaf(
      sender,
      senderBal,
      senderBlindingNonce
    );
    const senderRootBefore = senderWitness.calculateRoot(sdLeafDataBefore);
    senderRootBefore.assertEquals(privateRoot);

    //assert sender signature
    //TODO

    // //assert sender sufficient balance
    amount.assertLessThanOrEqual(senderBal);

    //assert recipient leaf
    //private recipient cannot be empty
    const rcpLeafDataBefore = this.blindPrivateLeaf(
      recipient,
      recipientBlindBal,
      recipientBlindHash
    );
    const recipientRootBefore =
      recipientWitness.calculateRoot(rcpLeafDataBefore);
    recipientRootBefore.assertEquals(privateRoot);

    //calculate new private sender leaf
    const leafData1 = this.privateLeaf(
      sender,
      senderBal.sub(amount),
      senderBlindingNonce
    );

    //calculate new private recipient leaf
    const leafData2 = this.blindPrivateLeaf(
      recipient,
      recipientBlindBal.add(amount),
      recipientBlindHash
    );

    //calculate new private root
    const privateRootAfter = calculateUpdate2Roots(
      senderWitness,
      recipientWitness,
      leafData1,
      leafData2
    );

    // set the new private root
    this.privateTreeRoot.set(privateRootAfter);

    //emit events for private sender leaf
    this.emitEvent('update-private-leaf-index', senderWitness.calculateIndex());
    this.emitEvent('update-private-leaf', leafData1);

    //emit events for private recipient leaf
    this.emitEvent(
      'update-private-leaf-index',
      recipientWitness.calculateIndex()
    );
    this.emitEvent('update-private-leaf', leafData2);
  }
}
