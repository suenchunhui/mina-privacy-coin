import 'dotenv/config';
import { MerkleListener, MerkleListenerLib } from './server.js';
import { Coin } from './Coin.js';
import {
  Mina,
  PublicKey,
} from 'o1js';

const height = 32;
const api_port = 30001;

const graphqlURL = "https://proxy.berkeley.minaexplorer.com/graphql"
const archiveURL = "https://archive.berkeley.minaexplorer.com/"
const ZkAppAddress58 = "" 

if (graphqlURL && ZkAppAddress58) {
  //setup network
  const MinaNetwork = Mina.Network({
    mina: graphqlURL,
    archive: archiveURL
  });
  Mina.setActiveInstance(MinaNetwork);
  console.log('Using network: ' + graphqlURL);

  //use deployed contract
  const zkAppAddress = PublicKey.fromBase58(
    ZkAppAddress58
  );
  const zkAppInstance = new Coin(zkAppAddress);
  console.log('Using deployed contract at: ' + ZkAppAddress58);

  const merkleListener = new MerkleListener(zkAppInstance, height, api_port);
  await merkleListener.start();

  //Fetch events every 10sec
  merkleListener.fetchEvents();
  setInterval(()=>{
    merkleListener.fetchEvents();
  }, 10000);
  
}else{
  console.log("NetworkURL and ZkAppAddress env missing.");
  process.exit(-1);
}
