extern crate rand;
use rand::thread_rng;

extern crate curve25519_dalek_ng;
use curve25519_dalek_ng::scalar::Scalar;

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

fn main() {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    let test1 = pc_gens.commit(Scalar::from(3u64), Scalar::from(1000u64));
    println!("test: {:?}",  Scalar::from_bytes_mod_order(*test1.compress().as_bytes()));
    let test2 = pc_gens.commit(Scalar::from(1u64), Scalar::from(200u64));
    println!("test: {:?}",  Scalar::from_bytes_mod_order(*test2.compress().as_bytes()));
    let test3 = pc_gens.commit(Scalar::from(1u64), Scalar::from(200u64));
    println!("test: {:?}",  Scalar::from_bytes_mod_order(*test3.compress().as_bytes()));
    let test4 = pc_gens.commit(Scalar::from(1u64), Scalar::from(600u64));
    println!("test: {:?}",  Scalar::from_bytes_mod_order(*test4.compress().as_bytes()));
    let test5 = test1 + test2 + test3;
    println!("test: {:?}", test1-test2-test3 == test4);


    // println!("test: {:?}", test4.compress() == test5.compress());

    // TODO: EVERYTHING I KNOW 
    // The commitment to 0 has to be with a random r
    // All the v and r have to subtract to 0 to hold homomorphic property
    // With a one-out-of-many proof, we can prove that one of the commitments is 0 by not revealing the r
    // With a one-out-of-many proof, we can prove that one of the commitments in the set has the same value as V by providing a new commitment to V with a new r
    // I can turn a point to a scalar and then back to a point. Addition seems to hold but probably doesn't. Why the fuck would I do this? To sum to amount?

    // This means that given we have two commitments in a set X. I can generate two random commitments that I can use to prove that I have two commitments in X that have the same value
    // These two random commitments can be used against some newly created output commitments to show the total is the same
    // All of this holds only if we can reduce the r to 0 (or same value?)

    // Problem: how to prevent sender from spending receiver's money
    // A serial number is generated from the receiver view key. This means that only the receiver should know how to generate the sn with the spend key to spend the money?? exactly how is beyond me

    // Problem: how to prevent from proving same thing in different commitments
    // Let's say that every commitment in the set is the sum of a C(amount) + C(sn) // maybe + C(r)???
    // Rewind: let's say that every commitment in the set is of form C(amount, C(sn))
    // I reveal two sn: sn1 and sn2. I should be able to prove that the sum of the two new commitments I have created is the same as sn1+sn2
    // I create two commitments for C(amount1) and C(amount2) and then I create two commitments for C(sn1) and C(sn2)



    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 16.
    let bp_gens = BulletproofGens::new(64, 16);

    // Four secret values we want to prove lie in the range [0, 2^32)
    let secrets = [4242344947u64, 3718732727u64, 2255562556u64, 2526146994u64];

    // The API takes blinding factors for the commitments.
    let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    // Create an aggregated 32-bit rangeproof and corresponding commitments.
    let (proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &secrets,
        &blindings,
        32,
    )
    .expect("A real program could handle errors");

    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &commitments,
            32
        )
        .is_ok());
}
