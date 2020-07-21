import SenateMerkleTree from "./senate-tree.js";
import CryptoJS from "crypto-js";
import pedersenHash from "./circomlib/src/pedersenHash.js";
import babyJub from "./circomlib/src/babyjub.js";
import crypto from "crypto";
import reverse from "buffer-reverse";
import console from "console";
import fs from "fs";
import ffjs from "ffjavascript";

const utils = ffjs.utils;

/**
 * Generate Tree
 */
const depth = 3;
let senate = new SenateMerkleTree(null, depth);
senate.init();

/**
 * Generate merkle proof
 */
let { proof, shouldSwitch } = senate.getProof(0);

let merkleProof = proof.map((p) => "0x" + p.toString("hex"));
let merkleRoot = senate.getRoot();
// console.log(senate.layers[0].map((t) => t.toString("hex")));
// console.log(senate.layers[1].map((t) => t.toString("hex")));
// console.log(senate.layers[2].map((t) => t.toString("hex")));
// console.log(senate.layers[3].map((t) => t.toString("hex")));

/**
 * Generate vote commitment
 */
let { secret, t1, t2, addr, nullifier } = senate.voters[0];
let vote = crypto.randomBytes(16);
let electionId = crypto.randomBytes(16);
let S = crypto.randomBytes(16);
let voteCommitment = senate.voters[0].generateVoteCommitment(vote, electionId);

/**
 * Generate eligibility criterion (R)
 */
let eligibilityHash = babyJub.unpackPoint(
  pedersenHash.hash(Buffer.concat([reverse(t1), reverse(S)]))
)[0];

/**@type {Buffer}*/
let buff = utils.leInt2Buff(eligibilityHash, 32);
let leastSig = utils.leBuff2int(buff.slice(0, 16));
let R = leastSig + BigInt(1);

/**
 * Final input object
 */
let inputsAsNums = {
  addr: "0x" + addr.toString("hex"),
  voteCommitment: "0x" + voteCommitment,
  merkleRoot: "0x" + merkleRoot,
  secret: "0x" + secret.toString("hex"),

  t1: "0x" + t1.toString("hex"),
  t2: "0x" + t2.toString("hex"),
  vote: "0x" + vote.toString("hex"),
  electionId: "0x" + electionId.toString("hex"),
  nullifier: "0x" + nullifier.toString("hex"),
  merkleProof,
  shouldSwitch,
  S: "0x" + S.toString("hex"),
  R: R.toString(),
};

console.log(inputsAsNums);
fs.writeFileSync("./input.json", JSON.stringify(inputsAsNums));
