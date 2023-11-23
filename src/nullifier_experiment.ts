import {
  PrivateKey,
  PublicKey,
  Nullifier,
  Field,
  SmartContract,
  state,
  State,
  method,
  MerkleMap,
  Circuit,
  MerkleMapWitness,
  Mina,
  AccountUpdate,
} from 'o1js';

class PayoutOnlyOnce extends SmartContract {
  @state(Field) nullifierRoot = State<Field>();
  @state(Field) nullifierMessage = State<Field>();
  @state(PublicKey) allowedPk = State<PublicKey>();

  @method payout(nullifier: Nullifier) {
    let nullifierRoot = this.nullifierRoot.getAndAssertEquals();
    let nullifierMessage = this.nullifierMessage.getAndAssertEquals();
    let allowedPk = this.allowedPk.getAndAssertEquals();

    // verify the nullifier
    nullifier.verify([nullifierMessage]);
    allowedPk.assertEquals(nullifier.getPublicKey());

    let nullifierWitness = Circuit.witness(MerkleMapWitness, () =>
      NullifierTree.getWitness(nullifier.key())
    );

    // we compute the current root and make sure the entry is set to 0 (= unused)
    nullifier.assertUnused(nullifierWitness, nullifierRoot);

    // we set the nullifier to 1 (= used) and calculate the new root
    let newRoot = nullifier.setUsed(nullifierWitness);

    // we update the on-chain root
    this.nullifierRoot.set(newRoot);

    // we pay out a reward
    let balance = this.account.balance.getAndAssertEquals();

    let halfBalance = balance.div(2);
    // finally, we send the payout to the public key associated with the nullifier
    this.send({ to: nullifier.getPublicKey(), amount: halfBalance });
  }
}

const NullifierTree = new MerkleMap();

let Local = Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);

// a test account that pays all the fees, and puts additional funds into the zkapp
let { privateKey: senderKey, publicKey: sender } = Local.testAccounts[0];

// the zkapp account
let zkappKey = PrivateKey.random();
let zkappAddress = zkappKey.toPublicKey();

// a special account that is allowed to pull out half of the zkapp balance, once
let privilegedKey = PrivateKey.random();
let privilegedAddress = privilegedKey.toPublicKey();

// an account that is *NOT* allowed to pull out half of the zkapp balance, once
let unprivilegedKey = PrivateKey.random();
let unprivilegedAddress = unprivilegedKey.toPublicKey();

let initialBalance = 10_000_000_000;
let zkapp = new PayoutOnlyOnce(zkappAddress);

// a unique message
let nullifierMessage = Field(5);

console.log('compile');
await PayoutOnlyOnce.compile();

console.log('deploy');
let tx = await Mina.transaction(sender, () => {
  let senderUpdate = AccountUpdate.fundNewAccount(sender);
  senderUpdate.send({ to: zkappAddress, amount: initialBalance });
  zkapp.deploy({ zkappKey });

  zkapp.nullifierRoot.set(NullifierTree.getRoot());
  zkapp.nullifierMessage.set(nullifierMessage);
  zkapp.allowedPk.set(privilegedAddress);
});
await tx.prove();
await tx.sign([senderKey]).send();

console.log(`zkapp balance: ${zkapp.account.balance.get().div(1e9)} MINA`);

console.log('trying pay out using unprivilegedKey');

let jsonNullifier2 = Nullifier.createTestNullifier(
  [nullifierMessage],
  unprivilegedKey
);
//console.log(jsonNullifier2);

try {
  tx = await Mina.transaction(sender, () => {
    zkapp.payout(Nullifier.fromJSON(jsonNullifier2));
  });

  await tx.prove();
  await tx.sign([senderKey]).send();
} catch (error: any) {
  console.log(
    'transaction failed, as expected! received the following error message:'
  );
  //console.log(error.message);
}

console.log('trying pay out using wrong msg');

let jsonNullifier3 = Nullifier.createTestNullifier([Field(6)], unprivilegedKey);
//console.log(jsonNullifier2);

try {
  tx = await Mina.transaction(sender, () => {
    zkapp.payout(Nullifier.fromJSON(jsonNullifier3));
  });

  await tx.prove();
  await tx.sign([senderKey]).send();
} catch (error: any) {
  console.log(
    'transaction failed, as expected! received the following error message:'
  );
  //console.log(error.message);
}

console.log('generating nullifier');

let jsonNullifier = Nullifier.createTestNullifier(
  [nullifierMessage],
  privilegedKey
);
console.log(jsonNullifier);

let jsonNullifier_dup = Nullifier.createTestNullifier(
  [nullifierMessage],
  privilegedKey
);
console.log(jsonNullifier_dup);

console.log('pay out');
tx = await Mina.transaction(sender, () => {
  AccountUpdate.fundNewAccount(sender);
  zkapp.payout(Nullifier.fromJSON(jsonNullifier));
});
await tx.prove();
await tx.sign([senderKey]).send();

console.log(`zkapp balance: ${zkapp.account.balance.get().div(1e9)} MINA`);
console.log(
  `user balance: ${Mina.getAccount(privilegedAddress).balance.div(1e9)} MINA`
);

console.log('trying second pay out');

try {
  tx = await Mina.transaction(sender, () => {
    zkapp.payout(Nullifier.fromJSON(jsonNullifier));
  });

  await tx.prove();
  await tx.sign([senderKey]).send();
} catch (error: any) {
  console.log(
    'transaction failed, as expected! received the following error message:'
  );
  console.log(error.message);
}
