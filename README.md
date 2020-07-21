# Subsenate

zkSnark based random subset voting.

## How to run it?
1. Install dependencies:
```bash
npm install
```
2. Compile the circuit and run the setup
```bash
./node_modules/.bin/circom subsenate.circom --wasm --r1cs --sym
./node_modules/.bin/snarkjs setup -r subsenate.r1cs
```
3. Generate inputs (either yourself or using the supplied generate test inputs script)
```bash
node generate-test-inputs.js
```
4. Calculate the witness, create and verify the proof.
```bash
./node_modules/.bin/snarkjs calculatewitness --wasm subsenate.wasm --input input.json --witness witness.json
./node_modules/.bin/snarkjs proof
./node_modules/.bin/snarkjs verify
```