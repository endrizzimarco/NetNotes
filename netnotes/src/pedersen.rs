#![allow(non_snake_case)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use one_of_many_proofs::proofs::ProofGens;

lazy_static! {
    // supports sets of up to 32 commitments in the one-out-of-many proof
    static ref GENS: ProofGens = ProofGens::new(5).unwrap();
}

pub type Commitment = RistrettoPoint;

pub fn commit(value: Scalar, r: Scalar) -> Commitment {
    GENS.commit(&value, &r).unwrap()
}

pub fn commit_G(value: Scalar) -> Commitment {
    GENS.commit(&Scalar::zero(), &value).unwrap()
}

pub fn commit_H(value: Scalar) -> Commitment {
    GENS.commit(&value, &Scalar::zero()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants;
    use rand::rngs::OsRng;
    use sha3::Sha3_512;

    #[test]
    fn test_pedersen_commitment() {
        // set up G and H
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let expected = value * H + r * G;

        // compute the actual commitment using the commit function
        let commitment = commit(value, r);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());
    }

    #[test]
    fn test_pedersen_commitment_unblinded_G() {
        // set up G
        let G = constants::RISTRETTO_BASEPOINT_POINT;

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * G;

        // compute the actual commitment using the commit function
        let commitment = commit_G(value);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());
    }

    #[test]
    fn test_pedersen_commitment_unblinded_H() {
        // set up G
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * H;

        // compute the actual commitment using the commit function
        let commitment = commit_H(value);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());
    }

    #[test]
    fn test_homorphic_properties() {
        // set up G and H
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let expected = value * H + r * G;

        // compute the actual commitment using the commit function
        let commitment = commit(value, r);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());

        // check homorphic properties
        let value2 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        let expected2 = value2 * H + r2 * G;
        let commitment2 = commit(value2, r2);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment2.compress(), expected2.compress());

        // check homorphic properties
        let expected3 = expected + expected2;
        let commitment3 = commitment + commitment2;

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment3.compress(), expected3.compress());
    }

    #[test]
    fn test_pedersen_commitment_unblinded_homorphic_properties() {
        // set up G
        let G = constants::RISTRETTO_BASEPOINT_POINT;

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * G;

        // compute the actual commitment using the commit function
        let commitment = commit_G(value);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());

        // check homorphic properties
        let value2 = Scalar::random(&mut OsRng);
        let expected2 = value2 * G;
        let commitment2 = commit_G(value2);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment2.compress(), expected2.compress());

        // check homorphic properties
        let expected3 = expected + expected2;
        let commitment3 = commitment + commitment2;

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment3.compress(), expected3.compress());
    }
}
