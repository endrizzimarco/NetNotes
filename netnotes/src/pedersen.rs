use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use one_of_many_proofs::proofs::ProofGens;
use rand::rngs::OsRng;
use sha3::Sha3_512;

lazy_static! {
    // supports sets of up to 32 commitments in the one-out-of-many proof
    static ref GENS: ProofGens = ProofGens::new(5).unwrap();
}

struct Pedersen;
impl Pedersen {
    pub fn commit(value: Scalar, r: Scalar) -> RistrettoPoint {
        GENS.commit(&value, &r).unwrap()
    }

    pub fn commit_unblinded(value: Scalar) -> RistrettoPoint {
        GENS.commit(&value, &Scalar::zero()).unwrap()
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment() {
        // set up G and H
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let expected = value * H + r * G;

        // compute the actual commitment using the Pedersen::commit function
        let commitment = Pedersen::commit(value, r);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());
    }

    #[test]
    fn test_pedersen_commitment_unblinded() {
        // set up G and H
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * H;

        // compute the actual commitment using the Pedersen::commit function
        let commitment = Pedersen::commit_unblinded(value);

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

        // compute the actual commitment using the Pedersen::commit function
        let commitment = Pedersen::commit(value, r);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());

        // check homorphic properties
        let value2 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        let expected2 = value2 * H + r2 * G;
        let commitment2 = Pedersen::commit(value2, r2);

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
        // set up G and H
        let G = constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha3_512>(G.compress().as_bytes());

        // compute the expected commitment with random value and r
        let value = Scalar::random(&mut OsRng);
        let expected = value * H;

        // compute the actual commitment using the Pedersen::commit function
        let commitment = Pedersen::commit_unblinded(value);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment.compress(), expected.compress());

        // check homorphic properties
        let value2 = Scalar::random(&mut OsRng);
        let expected2 = value2 * H;
        let commitment2 = Pedersen::commit_unblinded(value2);

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment2.compress(), expected2.compress());

        // check homorphic properties
        let expected3 = expected + expected2;
        let commitment3 = commitment + commitment2;

        // check if the actual commitment matches the expected commitment
        assert_eq!(commitment3.compress(), expected3.compress());
    }
}
