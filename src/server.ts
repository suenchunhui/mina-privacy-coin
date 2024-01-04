import express, { Express, Request, Response } from 'express';
import { Coin } from './Coin.js';
import {
  Field,
  MerkleTree,
  MerkleMap,
  UInt32,
} from 'o1js';

//const events = await zkapp.fetchEvents(UInt32.from(0));
// Fetch all events starting at block 560 and ending at block 600
//const events = await zkapp.fetchEvents(UInt32.from(560), UInt32.from(600));

class MerkleListener {
  coinInstance: Coin;
  publicTree: MerkleTree;
  privateTree: MerkleTree;
  nullifierTree: MerkleMap;
  lastFetched: UInt32 = UInt32.from(0);
  server;

  constructor(inst: Coin, height: number, serverPort = -1) {
    this.coinInstance = inst;
    this.publicTree = new MerkleTree(height);
    this.privateTree = new MerkleTree(height);
    this.nullifierTree = new MerkleMap();

    //express server to return tree root and witness using rest api
    if (serverPort > 0) {
      let app = express();
      app.get('/:tree/:fn', (req: Request, res: Response) => {
        let tree: MerkleTree | MerkleMap;
        switch (req.params.tree) {
          case 'public':
            tree = this.publicTree;
            break;
          case 'private':
            tree = this.privateTree;
            break;
          case 'nullifier':
            tree = this.nullifierTree;
            break;
  
            default:
            throw Error('Undefined tree selector');
        }

        switch (req.params.fn) {
          case 'root':
            res.json(tree.getRoot().toJSON());
            break;
          case 'witness':
            if (req.query.index) {
              let w;
              if(tree instanceof MerkleTree){
                w = tree.getWitness(BigInt(req.query.index.toString()));
              }else{
                w = tree.getWitness(Field(req.query.index.toString()));
              }
              res.send(JSON.stringify(w));
            } else {
              throw Error('Missing witness index');
            }
            break;
          default:
            throw Error('Undefined function selector');
        }
      });

      this.server = app.listen(serverPort, () => {
        console.log(`MerkleListener rest api started on port ${serverPort}`);
      });
    }
  }

  async fetchEvents() {
    //fetch events
    const events = await this.coinInstance.fetchEvents(
      UInt32.from(this.lastFetched)
    );

    let public_leaf: Field = Field(-1);
    let private_leaf: Field = Field(-1);

    //process events
    //console.log(events);
    events.forEach((e) => {
      if (e.blockHeight > this.lastFetched) 
        this.lastFetched = e.blockHeight;

      switch (e.type) {
        case 'update-public-leaf':
          public_leaf = e.event.data.toFields(0)[0];
          break;
        case 'update-public-leaf-index':
          let public_index = e.event.data.toFields(0)[0].toBigInt();
          if (public_index != -1n && public_leaf != Field(-1)) {
            this.publicTree.setLeaf(public_index, public_leaf);
            public_leaf = Field(-1);
          }
          break;
        case 'update-private-leaf':
          private_leaf = e.event.data.toFields(0)[0];
          break;
        case 'update-private-leaf-index':
          let private_index = e.event.data.toFields(0)[0].toBigInt();
          if (private_index != -1n && private_leaf != Field(-1)) {
            this.privateTree.setLeaf(private_index, private_leaf);
            private_leaf = Field(-1);
          }
          break;
        case 'update-nullifier-leaf-index':
          let nullifier_index = e.event.data.toFields(0)[0].toBigInt();
          this.nullifierTree.set(Field(nullifier_index), Field(1));
          break;
      }
    });
  }

  shutdown() {
    if (this.server) {
      this.server.close(() => {
        //console.log('Server closed');
      });
    }
  }
}

export default MerkleListener;
