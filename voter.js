import CryptoJS from "crypto-js";
import elliptic from "elliptic";
import pedersenHash from "./circomlib/src/pedersenHash.js";
import crypto from "crypto";
import babyJub from "./circomlib/src/babyjub.js";
import reverse from "buffer-reverse";
import ffjs from "ffjavascript";

const utils = ffjs.utils;
var ec = new elliptic.ec("secp256k1");

class Voter {
  /**
   *
   * @param {Buffer} secret
   * @param {Buffer} addr
   * @param {Buffer} t1
   * @param {Buffer} t2
   * @param {Buffer} nullifier
   * @param {Buffer} privateKey
   * @param {Buffer} publicKey
   */
  constructor(secret, addr, t1, t2, nullifier, privateKey, publicKey) {
    this.secret = secret;
    this.addr = addr;
    this.t1 = t1;
    this.t2 = t2;
    this.nullifier = nullifier;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * @return {Buffer}
   */
  generateIdCommitment() {
    let { secret, t1, t2 } = this;
    let pre = Buffer.concat([
      reverse(secret),
      reverse(t1),
      reverse(t2),
      //Buffer.alloc(16),
    ]);
    // console.log(pre.toString("hex"));
    let hashDigest = pedersenHash.hash(pre);
    // console.log(babyJub.unpackPoint(hashDigest)[0].toString(16));
    return utils.leInt2Buff(babyJub.unpackPoint(hashDigest)[0], 32);
    //return hashDigest.toString(CryptoJS.enc.Hex);
  }

  /**
   *
   * @param {Buffer} vote
   * @param {Buffer} electionId
   */
  generateVoteCommitment(vote, electionId) {
    let { secret, addr, nullifier } = this;

    let pre = Buffer.concat([
      reverse(secret),
      reverse(vote),
      reverse(electionId),
      reverse(nullifier),
      reverse(addr),
      Buffer.alloc(12),
    ]);

    let hashDigest = pedersenHash.hash(pre);
    return babyJub.unpackPoint(hashDigest)[0].toString(16);

    //    return hashDigest.toString(CryptoJS.enc.Hex);
  }

  static createRandomVoter() {
    // Private key generation

    var key = ec.genKeyPair();

    let privateKey = Buffer.from(key.getPrivate().toString(16), "hex");
    let publicKey = Buffer.from(key.getPublic().encode("hex", false), "hex");
    let ethAddr = Buffer.from(
      CryptoJS.SHA256(publicKey.toString("hex"))
        .toString(CryptoJS.enc.Hex)
        .substring(24),
      "hex"
    );

    let secret = crypto.randomBytes(16);

    let t1 = crypto.randomBytes(16);
    let t2 = crypto.randomBytes(16);
    let nullifier = crypto.randomBytes(16);

    return new Voter(secret, ethAddr, t1, t2, nullifier, privateKey, publicKey);
  }
}

export default Voter;
