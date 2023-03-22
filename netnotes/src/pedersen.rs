#![allow(non_snake_case)]
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use one_of_many_proofs::proofs::ProofGens;
use sha3::Keccak512;

lazy_static! {
    // supports sets of up to 32 commitments in the one-out-of-many proof
    static ref GENS: ProofGens = ProofGens::new(5).unwrap();
    static ref J: RistrettoBasepointTable = RistrettoBasepointTable::create(
        &RistrettoPoint::hash_from_bytes::<Keccak512>(G.compress().as_bytes())
    );
}

pub type Commitment = RistrettoPoint;

// s.J + v.H + r.G
pub fn generalised_commit(value: Scalar, r: Scalar, s: Scalar) -> Commitment {
    commit_J(s) + GENS.commit(&value, &r).unwrap()
}

// v.H + r.G
pub fn commit(value: Scalar, r: Scalar) -> Commitment {
    GENS.commit(&value, &r).unwrap()
}

// s.J + v.H
pub fn commit_hj(value: Scalar, r: Scalar) -> Commitment {
    commit_H(value) + commit_J(r)
}

pub fn commit_G(value: Scalar) -> Commitment {
    GENS.commit(&Scalar::zero(), &value).unwrap()
}

pub fn commit_H(value: Scalar) -> Commitment {
    GENS.commit(&value, &Scalar::zero()).unwrap()
}

pub fn commit_J(value: Scalar) -> RistrettoPoint {
    &*J * &value
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use sha3::Sha3_512;

    #[test]
    fn test_pedersen_commitment() {
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let expected = value * H + r * G;

        // compute the actual commitment using the commit function
        let commitment = commit(value, r);

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_pedersen_commitment_unblinded_G() {
        let value = Scalar::random(&mut OsRng);
        let expected = value * G;

        // compute the actual commitment using the commit function
        let commitment = commit_G(value);

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_pedersen_commitment_unblinded_H() {
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * H;

        // compute the actual commitment using the commit function
        let commitment = commit_H(value);

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_single_unblinded_commitments() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);

        let G_commitment = commit_G(scalar2);
        let H_commitment = commit_H(scalar1);
        let commitment = commit(scalar1, scalar2);

        // check if the actual commitment matches the reconstructed commitment
        assert_eq!(commitment, G_commitment + H_commitment);
    }

    #[test]
    fn test_generalised_commitment() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        let scalar3 = Scalar::random(&mut OsRng);

        let G_commitment = commit_G(scalar2);
        let H_commitment = commit_H(scalar1);
        let J_commitment = commit_J(scalar3);
        let expected = generalised_commit(scalar1, scalar2, scalar3);

        // check if the generalised commitment matches the sum of individual commitments
        assert_eq!(expected, G_commitment + H_commitment + J_commitment);
    }

    #[test]
    fn test_homomorphic_generalised_commitment() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        let scalar3 = Scalar::random(&mut OsRng);

        let generalised_commitment = generalised_commit(scalar1, scalar2, scalar3);
        let HJ_commitment = commit_hj(scalar1, scalar3);
        let expected = commit(Scalar::zero(), scalar2);

        // s.J + v.H + r.G - (s.J + v.H) = r.G
        assert_eq!(expected, generalised_commitment - HJ_commitment);
    }

    #[test]
    fn test_homorphic_properties() {
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        let value = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let commitment = commit(value, r);

        let value2 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        let commitment2 = commit(value2, r2);

        // check homorphic properties
        let expected = (value + value2) * H + (r + r2) * G;
        let commitment_sum = commitment + commitment2;

        assert_eq!(expected, commitment_sum);
    }
}
