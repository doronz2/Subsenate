rm -rf proof.json input.json public.json
node generate-test-inputs.js
./node_modules/.bin/snarkjs calculatewitness --wasm subsenate.wasm --input input.json --witness witness.json
./node_modules/.bin/snarkjs proof
./node_modules/.bin/snarkjs verify
