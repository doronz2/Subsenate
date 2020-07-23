rm -rf proof.json verification_key.json witness.json public_key.json input.json proving_key.json public.json
./node_modules/.bin/circom subsenate.circom --wasm --r1cs --sym
./node_modules/.bin/snarkjs setup -r subsenate.r1cs
node generate-test-inputs.js
./node_modules/.bin/snarkjs calculatewitness --wasm subsenate.wasm --input input.json --witness witness.json
./node_modules/.bin/snarkjs proof
./node_modules/.bin/snarkjs verify
