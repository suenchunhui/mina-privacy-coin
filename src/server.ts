import { Coin } from './Coin.js';
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
  UInt32,
} from 'o1js';

//const events = await zkapp.fetchEvents(UInt32.from(0));
// Fetch all events starting at block 560 and ending at block 600
//const events = await zkapp.fetchEvents(UInt32.from(560), UInt32.from(600));

class MerkleListener {
  coinInstance: Coin;
  publicTree: MerkleTree;
  privateTree: MerkleTree;
  lastFetched: UInt32 = UInt32.from(0);

  constructor(inst: Coin, height: number) {
    this.coinInstance = inst;
    this.publicTree = new MerkleTree(height);
    this.privateTree = new MerkleTree(height);
  }

  async fetchEvents() {
    //fetch events
    const events = await this.coinInstance.fetchEvents(
      UInt32.from(this.lastFetched)
    );

    let public_leaf: Field = Field(-1);
    let public_index = -1n;
    let private_leaf: Field = Field(-1);
    let private_index = -1n;

    //process events
    //console.log(events);
    events.forEach((e) => {
      if (e.blockHeight > this.lastFetched) this.lastFetched = e.blockHeight;

      //console.log(e.event.data, e.event.transactionInfo, e.type);
      //console.log(e.event.data.toFields(0)[0]);

      switch (e.type) {
        case 'update-public-leaf':
          public_leaf = e.event.data.toFields(0)[0];
          break;
        case 'update-public-leaf-index':
          public_index = e.event.data.toFields(0)[0].toBigInt();
          break;
        case 'update-private-leaf':
          private_leaf = e.event.data.toFields(0)[0];
          break;
        case 'update-private-leaf-index':
          private_index = e.event.data.toFields(0)[0].toBigInt();
          break;
      }
    });

    //update tree(s)
    if (public_index != -1n && public_leaf != Field(-1)) {
      this.publicTree.setLeaf(public_index, public_leaf);
      console.log(
        `  Updating public tree: index=${public_index} value=${public_leaf}`
      );
    }
    if (private_index != -1n && private_leaf != Field(-1)) {
      this.privateTree.setLeaf(private_index, private_leaf);
      console.log(
        `  Updating private tree: index=${private_index} value=${private_leaf}`
      );
    }
  }
}

export default MerkleListener;
