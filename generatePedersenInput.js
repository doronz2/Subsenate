import pedersenHash from "./circomlib/src/pedersenHash.js";
import babyJub from "./circomlib/src/babyjub.js";
import ff from "ffjavascript";
import reverse from "buffer-reverse";

const Fr = ff.bn128.Fr;

const b0 = Buffer.alloc(32).fill(13);

const buf = Buffer.alloc(32);
for (let i = 0; i < 32; i++) buf[i] = 0xff;
//buf[31] = 0x1f;
// console.log(buf.reverse().toString("hex"));
const h0 = pedersenHash.hash(b0);
// const a = Buffer.alloc(16).toString("hex");
const bitN = BigInt("0x" + b0.toString("hex")).toString(2);
const a = h0.toString("hex").padEnd(32, 0).substring(0, 32);
// const b = Buffer.alloc(16).toString("hex");
const b = h0.toString("hex").padEnd(32, 0).substring(32, 64);

const c = b;
// const b = BigInt("0b" + bitN.substr(128, 256).padEnd(128, "1"));
// console.log(a.toString(2).length, b.toString(2).length);
const aBuf = Buffer.from(a, "hex");
const bBuf = Buffer.from(b, "hex");
const cBuf = Buffer.from(c, "hex");

const pre = Buffer.concat([reverse(aBuf), reverse(bBuf), reverse(cBuf)]);

const h = pedersenHash.hash(pre);

const hP = babyJub.unpackPoint(h);
const inp = {
  //n: n.toString(),
  a: "0x" + a.toString(),
  b: "0x" + b.toString(),
  c: "0x" + c.toString(),
  //   a: BigInt("0x" + a).toString(),
  //   b: BigInt("0x" + b).toString(),
  outTest: hP[0].toString(),
};

console.log(JSON.stringify(inp));
// console.log(a.length, b.length);
