import CryptoJS from "crypto-js";
import Voter from "./voter.js";
import pedersenHash from "./circomlib/src/pedersenHash.js";
import babyJub from "./circomlib/src/babyjub.js";
import ffjs from "ffjavascript";

const utils = ffjs.utils;

/** @type {Buffer} */
const BLANK = pedersenHash.hash("BLANK");

/**
 *
 * @param {Buffer} leftChild
 * @param {Buffer} rightChild
 * @return {Buffer}
 */
function generateHash(leftChild, rightChild) {
  var parent = null;

  let pre;
  if (utils.leBuff2int(leftChild) < utils.leBuff2int(rightChild)) {
    pre = Buffer.concat([leftChild, rightChild]);
  } else {
    pre = Buffer.concat([rightChild, leftChild]);
  }

  parent = pedersenHash.hash(pre);

  const hash = utils.leInt2Buff(babyJub.unpackPoint(parent)[0], 32);

  return hash;
}

/**
 *
 * @param {Buffer} a
 * @param {Buffer} b
 * @return {number} 0 if a < b and 1 if a > b
 */
function compareBuffers(a, b) {
  return utils.leBuff2int(a) < utils.leBuff2int(b) ? 0 : 1;
}

class SenateMerkleTree {
  constructor(commitments, depth = 10) {
    // If commitments are not seeded generate random voters

    /** @type {Array.<Array.<Buffer>>} */
    this.layers = [];
    if (commitments === null) {
      /** @type {Array.<Buffer>} */
      this.commitments = [];

      /** @type {Array.<Voter>}*/
      this.voters = [];
      for (var i = 0; i < 2 ** depth; i++) {
        let voter = Voter.createRandomVoter();
        this.voters.push(voter);
        this.commitments.push(voter.generateIdCommitment());
      }
    } else {
      this.commitments = commitments;
    }
  }

  init() {
    this.generateTree(this.commitments);
  }

  generateTree(commitments) {
    let newLayer = commitments.reduce(this.generateParentLayer, []);
    this.layers = [newLayer, commitments];
    while (this.layers[0].length > 1) {
      newLayer = this.layers[0].reduce(this.generateParentLayer, []);
      this.layers = [newLayer, ...this.layers];
    }
    this.root = this.layers[0][0];
  }

  /**
   *
   * @param {Array.<Buffer>} parentLayer
   * @param {Buffer} currentNode
   * @param {number} idx
   * @param {Array.<Buffer>} layer
   * @return {Array.<Buffer>}
   */
  generateParentLayer(parentLayer, currentNode, idx, layer) {
    if (idx % 2 === 1) {
      return parentLayer;
    }
    let nextNode = idx + 1 === layer.length ? BLANK : layer[idx + 1];
    return [...parentLayer, generateHash(currentNode, nextNode)];
  }

  getRoot() {
    return utils.leBuff2int(this.root).toString(16);
  }

  generateProofForLeafIdx(commitmentIdx) {
    let proof = [];
    let shouldSwitch = [];
    let index = commitmentIdx;
    for (let i = this.layers.length - 1; i > 0; i--) {
      let layer = this.layers[i];
      if (index + 1 === layer.length) {
        proof.push(BLANK);
        index = Math.floor(index / 2);
        continue;
      }
      let matchingNode = index % 2 === 0 ? layer[index + 1] : layer[index - 1];
      shouldSwitch.push(compareBuffers(layer[index], matchingNode));
      proof.push(matchingNode);
      index = Math.floor(index / 2);
    }
    proof = proof.map((v) => utils.leBuff2int(v).toString(16));
    return { proof, shouldSwitch };
  }

  getProof(commitmentIdx) {
    return this.generateProofForLeafIdx(commitmentIdx);
  }

  /**
   *
   * @param {Buffer} commitment
   * @param {Array.<Buffer>} proof
   */
  validateProof(commitment, proof) {
    const computedRoot = proof.reduce(
      (acc, hash) => generateHash(acc, hash),
      commitment
    );

    return computedRoot.toString("hex") == this.getRoot();
  }
}

export default SenateMerkleTree;
