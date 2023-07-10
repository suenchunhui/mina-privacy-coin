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
} from 'snarkyjs';

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

  let idx1 = witness1.calculateIndex();
  let idx2 = witness2.calculateIndex();

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

    idx1 = idx1_next;
    idx2 = idx2_next;
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

  //TODO payment for minting
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
    //sender
    senderWitness: MerkleWitness32,
    sender: PublicKey,
    senderBal: Field,
    //recipient
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
    amount.assertLte(senderBal);

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

  // @method transferToShielded(
  //   senderWitness: MerkleWitness32,
  //   recipient: PublicKey,
  //   shieldedIndex: Field,
  //   senderBal: Field,
  //   amount: Field
  // ) {

  //   const initialPublicRoot = this.publicTreeRoot.get();
  //   this.publicTreeRoot.assertEquals(initialPublicRoot);

  //   // check the initial state matches what we expect
  //   const senderRootBefore = senderWitness.calculateRoot(currentBal);
  //   senderRootBefore.assertEquals(initialPublicRoot);

  //   //incrementAmount.assertLt(Field(10));

  //   // compute the root after incrementing
  //   const rootAfter = leafWitness.calculateRoot(
  //       this.publicLeaf(recipient, currentBal.add(incrementAmount))
  //   );

  //   // set the new root
  //   this.publicTreeRoot.set(rootAfter);
  // }

  //   @method transfer(
  //     senderWitness: MerkleWitness32,
  //     recipientWitness: MerkleWitness32,

  //     recipient: PublicKey,
  //     currentBal: Field,
  //     incrementAmount: Field
  //   ) {
  //     const initialPublicRoot = this.publicTreeRoot.get();
  //     this.publicTreeRoot.assertEquals(initialPublicRoot);

  //     // check the initial state matches what we expect
  //     const senderRootBefore = senderWitness.calculateRoot(currentBal);
  //     senderRootBefore.assertEquals(initialPublicRoot);

  //     //incrementAmount.assertLt(Field(10));

  //     // compute the root after incrementing
  //     const rootAfter = leafWitness.calculateRoot(
  //         this.publicLeaf(recipient, currentBal.add(incrementAmount))
  //     );

  //     // set the new root
  //     this.publicTreeRoot.set(rootAfter);
  //   }
}
