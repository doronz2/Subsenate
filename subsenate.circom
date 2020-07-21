include "./circomlib/circuits/pedersen.circom";   
include "./circomlib/circuits/bitify.circom";
include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/switcher.circom";


//Hash of 128 bit secret, t1, t2
template CalculateIdentityCommitment(n) {
  signal input secret[n];
  signal input t1[n];
  signal input t2[n];

  signal output out;
 
  var numSlots = ((3*(n-1))\256)+1;
  component identity = Pedersen(3*n);

  for (var i = 0; i < n; i++) {
      identity.in[i] <== secret[i];
      identity.in[i+n] <== t1[i];
      identity.in[i+2*n] <== t2[i];
  }

  out <== identity.out[0];
}

// Hash of 128 bit secret, vote, electionId, nullifer (0 padded on the right) and 160 bit address 
template CalculateVoteCommitment(n) {
  signal input secret[n];
  signal input vote[n];
  signal input electionId[n];
  signal input nullifier[n];

  signal input address[160];

  signal output out;
 
  // Notice adding one extra slot for the address at the end
  var numSlots = ((4*(n-1))\256)+2;
  component voteCommitment = Pedersen(numSlots*256);

  var i;  
  for (i = 0; i < n; i++) {
      voteCommitment.in[i] <== secret[i];
      voteCommitment.in[i+n] <== vote[i];
      voteCommitment.in[i+2*n] <== electionId[i];
      voteCommitment.in[i+3*n] <== nullifier[i];
  }
  for (i = 0; i<160; i++){
      voteCommitment.in[i+4*n] <== address[i];
  }
  for (i = 160; i<256; i++){
      voteCommitment.in[i+4*n] <== 0;
  }

  out <== voteCommitment.out[0];
}

template MerkleHasher(){
    signal input a;
    signal input b;
    signal input swtch;
    signal output out;

    component hasher = Pedersen(512);
    component n2bLeft = Num2Bits(256);
    component n2bRight = Num2Bits(256);
    
    component switcher = Switcher();

    switcher.sel <-- swtch;
    switcher.L <-- a;
    switcher.R <-- b;
    
    n2bLeft.in <== switcher.outL;
    n2bRight.in <== switcher.outR;

    for(var j=0; j<256;j++){
        hasher.in[j] <== n2bLeft.out[j];
        hasher.in[j+256] <== n2bRight.out[j];
    }
    out <== hasher.out[0];
}   

template SenateVerifier(merkleDepth, numBits){
    signal private input secret;
    signal private input t1;
    signal private input t2;
    signal private input merkleProof[merkleDepth];
    signal private input shouldSwitch[merkleDepth];
    
    signal input vote;
    signal input addr;
    signal input electionId;
    signal input nullifier;
    signal input merkleRoot;
    signal input S;
    signal input R;
    signal input voteCommitment;
    
    signal output result;
    
    component secretNumToBit = Num2Bits(numBits);
    component t1NumToBit = Num2Bits(numBits);
    component t2NumToBit = Num2Bits(numBits);
    component voteNumToBit = Num2Bits(numBits);
    component nullifierNumToBit = Num2Bits(numBits);
    component electionIdToBit = Num2Bits(numBits);
    component SNumToBit = Num2Bits(numBits);

    component addrNumToBit = Num2Bits(160);

    secretNumToBit.in <== secret;
    t1NumToBit.in <== t1;
    t2NumToBit.in <== t2;
    nullifierNumToBit.in <== nullifier;
    electionIdToBit.in <== electionId;
    voteNumToBit.in <== vote;
    SNumToBit.in <== S;
    addrNumToBit.in <== addr;
    
    component idCommitmentCalculator = CalculateIdentityCommitment(numBits);
    component voteCommitmentCalculator = CalculateVoteCommitment(numBits);
    
    for (var i = 0; i<numBits;i++){
        idCommitmentCalculator.secret[i] <== secretNumToBit.out[i];
        idCommitmentCalculator.t1[i] <== t1NumToBit.out[i];
        idCommitmentCalculator.t2[i] <== t2NumToBit.out[i];

        
        voteCommitmentCalculator.secret[i] <== secretNumToBit.out[i];
        voteCommitmentCalculator.vote[i] <== voteNumToBit.out[i];
        voteCommitmentCalculator.electionId[i] <== electionIdToBit.out[i];
        voteCommitmentCalculator.nullifier[i] <== nullifierNumToBit.out[i];
    }

    for (var i = 0; i<160;i++){
        voteCommitmentCalculator.address[i] <== addrNumToBit.out[i];
    }

    // Verify the vote
    voteCommitment === voteCommitmentCalculator.out;

    component hashers[merkleDepth];
    signal hashes[merkleDepth + 1];
    hashes[0] <== idCommitmentCalculator.out;
    
    for (var i = 0; i<merkleDepth ;i++){
        hashers[i] = MerkleHasher();
        hashers[i].a <== hashes[i];
        hashers[i].b <== merkleProof[i];
        hashers[i].swtch <== shouldSwitch[i];
            
        
        hashes[i+1] <== hashers[i].out;
    }
    
    hashes[merkleDepth] === merkleRoot;

    // Verify eligibility
    component eligibilityHasher = Pedersen(2*numBits);
    
    for (var i = 0; i < numBits; i++){
        eligibilityHasher.in[i] <-- t1NumToBit.out[i];
        eligibilityHasher.in[i+numBits] <-- SNumToBit.out[i];
    }
    
    component leastSigBits = Num2Bits(256);
    leastSigBits.in <-- eligibilityHasher.out[0];

    component leastSigNum = Bits2Num(128);
    for (var i =0; i < 128; i++){
        leastSigNum.in[i] <== leastSigBits.out[i]
    }

    component comparator = LessThan(128);

    comparator.in[0] <== leastSigNum.out;
    comparator.in[1] <== R;

    comparator.out === 1;

    result <== 0;


}

component main = SenateVerifier(3,128);