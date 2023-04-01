#![allow(non_snake_case)]
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use one_of_many_proofs::proofs::ProofGens;
use sha3::Keccak512;

pub type Commitment = RistrettoPoint;
pub type GeneralisedCommitment = RistrettoPoint;

lazy_static! {
    static ref J: RistrettoBasepointTable = RistrettoBasepointTable::create(
        &RistrettoPoint::hash_from_bytes::<Keccak512>(G.compress().as_bytes())
    );
    pub static ref GENS: Pedersen = Pedersen::new(5);
    pub static ref GENS_MEDIUM: Pedersen = Pedersen::new(8);
    pub static ref GENS_LARGE: Pedersen = Pedersen::new(10);
}

pub struct Pedersen(pub ProofGens);

impl Pedersen {
    pub fn new(n_bits: usize) -> Self {
        Pedersen(ProofGens::new(n_bits).unwrap())
    }

    // s.G + r.H + v.J
    pub fn generalised_commit(&self, value: Scalar, r: Scalar, s: Scalar) -> GeneralisedCommitment {
        self.commit(r, s) + self.commit_J(value)
    }

    // v.H + r.G
    pub fn commit(&self, value: Scalar, r: Scalar) -> Commitment {
        self.0.commit(&value, &r).unwrap()
    }

    // r.H + v.J
    pub fn commit_hj(&self, value: Scalar, r: Scalar) -> Commitment {
        self.commit_H(value) + self.commit_J(r)
    }

    pub fn commit_G(&self, value: Scalar) -> Commitment {
        self.commit(Scalar::zero(), value)
    }

    pub fn commit_H(&self, value: Scalar) -> Commitment {
        self.commit(value, Scalar::zero())
    }

    pub fn commit_J(&self, value: Scalar) -> RistrettoPoint {
        &*J * &value
    }
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
        let commitment = GENS.commit(value, r);

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_pedersen_commitment_unblinded_G() {
        let value = Scalar::random(&mut OsRng);
        let expected = value * G;

        // compute the actual commitment using the commit function
        let commitment = GENS.commit_G(value);

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_pedersen_commitment_unblinded_H() {
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * H;

        // compute the actual commitment using the commit function
        let commitment = GENS.commit_H(value);

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_single_unblinded_commitments() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);

        let G_commitment = GENS.commit_G(scalar2);
        let H_commitment = GENS.commit_H(scalar1);
        let commitment = GENS.commit(scalar1, scalar2);

        // check if the actual commitment matches the reconstructed commitment
        assert_eq!(commitment, G_commitment + H_commitment);
    }

    #[test]
    fn test_generalised_commitment() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        let scalar3 = Scalar::random(&mut OsRng);

        let G_commitment = GENS.commit_G(scalar3);
        let H_commitment = GENS.commit_H(scalar2);
        let J_commitment = GENS.commit_J(scalar1);
        let expected = GENS.generalised_commit(scalar1, scalar2, scalar3);

        // check if the generalised commitment matches the sum of individual commitments
        assert_eq!(expected, G_commitment + H_commitment + J_commitment);
    }

    #[test]
    fn test_homomorphic_generalised_commitment() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        let scalar3 = Scalar::random(&mut OsRng);

        let generalised_commitment = GENS.generalised_commit(scalar1, scalar2, scalar3);
        let HJ_commitment = GENS.commit_hj(scalar2, scalar1);
        let expected = GENS.commit(Scalar::zero(), scalar3);

        // s.G + r.H + v.J - (v.J + r.H) = s.G
        assert_eq!(expected, generalised_commitment - HJ_commitment);
    }

    #[test]
    fn test_homorphic_properties() {
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        let value = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let commitment = GENS.commit(value, r);

        let value2 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        let commitment2 = GENS.commit(value2, r2);

        // check homorphic properties
        let expected = (value + value2) * H + (r + r2) * G;
        let commitment_sum = commitment + commitment2;

        assert_eq!(expected, commitment_sum);
    }
}
