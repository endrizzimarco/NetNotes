use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use one_of_many_proofs::proofs::{OneOfManyProofs, ProofGens};
use rand::rngs::OsRng;

#[allow(non_snake_case)]
fn main() {
    // Set up proof generators
    let J = constants::RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);
    let gens = ProofGens::new(5).unwrap();

    // == outputs ==

    // C(amount, r) - only used to check you are not creating money out of thin air
    let value = Scalar::from(2u32);
    let r = Scalar::random(&mut OsRng);
    let C_amount = gens.commit(&r, &value).unwrap(); // used in mw FIXME: wrong!

    // C(amount, r, s)
    let s = Scalar::random(&mut OsRng);
    let C_secret = gens.commit(&s, &r).unwrap() + J * &value;

    // Add C(amount, r, s) to the set
    let l: usize = 3; // The prover's commitment will be third in the set
                      // Build a random set containing the prover's commitment at index `l`
    let mut set = (1..gens.max_set_size())
        .map(|_| RistrettoPoint::random(&mut OsRng))
        .collect::<Vec<RistrettoPoint>>();
    set.insert(l, C_secret);

    // == inputs ==
    // C(amount, s) #FIXME: is this unique?
    let zero = Scalar::from(0u32);
    let C_sn = gens.commit(&s, &zero).unwrap() + J * &value;

    // Subtract the reveal C_sn from every commitment in the set
    set[l] = set[l] - C_sn;
    println!("set: {:?}", (C_secret - C_sn).compress());
    println!("C_sn: {:?}", gens.commit(&zero, &r).unwrap().compress());

    // Compute a `OneOfMany` membership proof for this commitment
    let t = Transcript::new(b"OneOfMany-Test");
    let proof = set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap();

    // Verify this membership proof, without any knowledge of `l` or `r`.
    assert!(set.iter().verify(&gens, &mut t.clone(), &proof).is_ok());
}
