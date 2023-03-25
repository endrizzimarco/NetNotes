#![allow(non_snake_case)]
use super::pedersen::{commit, commit_G, commit_H, commit_J, Commitment};
use blake3::Hasher;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

pub type PrivateKey = Scalar;

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct PublicKey(pub RistrettoPoint); // privateKey * G
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct PublicKeyJ(pub RistrettoPoint); // privateKey * H

pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

pub struct KeypairJ {
    pub public: PublicKeyJ,
    pub private: PrivateKey,
}

#[derive(PartialEq, Debug)]
pub struct Signature {
    s: Scalar,
    pub R: PublicKey,
}

pub struct GeneralisedSignature {
    s1: Scalar,
    s2: Scalar,
    pub R: PublicKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = PublicKey::from_private_key(private_key);

        Keypair {
            public: public_key,
            private: private_key,
        }
    }

    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = PublicKey::from_private_key(private_key);

        Keypair {
            public: public_key,
            private: private_key,
        }
    }
}

impl KeypairJ {
    pub fn generate() -> Self {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = PublicKeyJ::from_private_key(private_key);

        KeypairJ {
            public: public_key,
            private: private_key,
        }
    }

    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = PublicKeyJ::from_private_key(private_key);

        KeypairJ {
            public: public_key,
            private: private_key,
        }
    }
}

impl PublicKey {
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        PublicKey(commit_G(private_key))
    }
}

impl PublicKeyJ {
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        PublicKeyJ(commit_J(private_key))
    }
}

// PublicKey + PublicKey
impl std::ops::Add for PublicKey {
    type Output = PublicKey;

    fn add(self, other: PublicKey) -> PublicKey {
        PublicKey(self.0 + other.0)
    }
}

// PublicKeyJ + PublicKeyJ
impl std::ops::Add for PublicKeyJ {
    type Output = PublicKeyJ;

    fn add(self, other: PublicKeyJ) -> PublicKeyJ {
        PublicKeyJ(self.0 + other.0)
    }
}

// PublicKey + PublicKeyJ
impl std::ops::Add<PublicKeyJ> for PublicKey {
    type Output = PublicKey;

    fn add(self, other: PublicKeyJ) -> PublicKey {
        PublicKey(self.0 + other.0)
    }
}

impl Signature {
    pub fn new(nonce: &Keypair, private_key: &PrivateKey, challenge: Scalar) -> Self {
        // s = r + e * x
        let signature = nonce.private + challenge * private_key;

        Signature {
            s: signature,
            R: nonce.public,
        }
    }

    pub fn aggregate(partial_sigs: Vec<&Signature>) -> Self {
        let (s, R) = partial_sigs.iter().fold(
            (Scalar::zero(), PublicKey::from_private_key(Scalar::zero())),
            |acc, sig| (acc.0 + sig.s, acc.1 + sig.R),
        );

        Signature { s, R }
    }

    pub fn verify(signature: &Signature, public_key: &PublicKey, e: Scalar) -> bool {
        let sG = PublicKey::from_private_key(signature.s);
        let R = signature.R;

        // s.G == R + e.X
        sG.0 == R.0 + e * public_key.0
    }

    pub fn calculate_challenge(public_nonces: &PublicKey, public_keys: &PublicKey) -> Scalar {
        let mut hasher = Hasher::new();
        hasher.update("".as_bytes()); // sign on empty message
        hasher.update(public_nonces.0.compress().as_bytes());
        hasher.update(public_keys.0.compress().as_bytes());

        Scalar::from_bytes_mod_order(*hasher.finalize().as_bytes())
    }
}

impl GeneralisedSignature {
    // For signatures in the form r.G + s.J
    pub fn new_excess_proof(
        nonce1: &Keypair,
        nonce2: &KeypairJ,
        value: &PrivateKey,
        blinding_factor: &PrivateKey,
        challenge: Scalar,
    ) -> Self {
        // s1 = a + e * v
        let signature1 = nonce1.private + challenge * value;
        // s2 = b + e * r
        let signature2 = nonce2.private + challenge * blinding_factor;

        GeneralisedSignature {
            s1: signature1,
            s2: signature2,
            R: nonce1.public + nonce2.public,
        }
    }

    pub fn aggregate(partial_sigs: Vec<&GeneralisedSignature>) -> Self {
        let (s1, s2, R) = partial_sigs.iter().fold(
            (
                Scalar::zero(),
                Scalar::zero(),
                PublicKey::from_private_key(Scalar::zero()),
            ),
            |acc, sig| (acc.0 + sig.s1, acc.1 + sig.s2, acc.2 + sig.R),
        );

        GeneralisedSignature { s1, s2, R }
    }

    pub fn verify_excess_proof(
        signature: &GeneralisedSignature,
        commitment: Commitment,
        e: Scalar,
    ) -> bool {
        let s1G = PublicKey::from_private_key(signature.s1);
        let s2J = PublicKeyJ::from_private_key(signature.s2);
        let R = signature.R;

        // s1.G + s2.J == R + e.C
        s1G.0 + s2J.0 == R.0 + e * commitment
    }

    // For signatures in the form r.G + v.H
    pub fn new_input_proof(value: PrivateKey, blinding_factor: PrivateKey) -> GeneralisedSignature {
        let nonce1 = Scalar::random(&mut OsRng);
        let nonce2 = Scalar::random(&mut OsRng);
        let commitment = commit(value, blinding_factor);
        let nonces_commitment = commit(nonce1, nonce2);

        let challenge = Self::calculate_challenge(&commitment, &nonces_commitment);
        let s1 = nonce1 + challenge * value;
        let s2 = nonce2 + challenge * blinding_factor;
        let R = PublicKey(nonces_commitment);

        GeneralisedSignature { s1, s2, R }
    }

    // s1.H + s2.G == R + e.C
    pub fn verify_input_proof(signature: &GeneralisedSignature, commitment: Commitment) -> bool {
        let e = Self::calculate_challenge(&commitment, &signature.R.0);
        commit_H(signature.s1) + commit_G(signature.s2) == signature.R.0 + e * commitment
    }

    pub fn calculate_challenge(commitment: &Commitment, nonces_commitment: &Commitment) -> Scalar {
        let mut hasher = Hasher::new();
        hasher.update("".as_bytes()); // sign on empty message
        hasher.update(commitment.compress().as_bytes());
        hasher.update(nonces_commitment.compress().as_bytes());

        Scalar::from_bytes_mod_order(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::commit_hj;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use sha3::Keccak512;

    #[test]
    fn test_keypair_generation_1() {
        let keypair = Keypair::generate();
        let expected_public_key = PublicKey(RISTRETTO_BASEPOINT_POINT * keypair.private);
        // Verify that the public key can be reconstructed from the private key
        assert_eq!(keypair.public, expected_public_key);
    }

    #[test]
    fn test_keypair_generation_2() {
        let keypair = Keypair::generate();
        assert_eq!(keypair.public, PublicKey::from_private_key(keypair.private));
    }

    #[test]
    fn test_keypair_from_private_key() {
        let private_key = Scalar::random(&mut OsRng);
        let keypair = Keypair::from_private_key(private_key);
        assert_eq!(keypair.public, PublicKey::from_private_key(private_key));
        assert_eq!(keypair.private, private_key);
    }

    #[test]
    fn test_keypairJ_generation_1() {
        let keypair = KeypairJ::generate();
        let J = RistrettoPoint::hash_from_bytes::<Keccak512>(
            RISTRETTO_BASEPOINT_POINT.compress().as_bytes(),
        );
        let expected_public_key = PublicKeyJ(J * keypair.private);
        assert_eq!(keypair.public, expected_public_key);
    }

    #[test]
    fn test_keypairJ_generation_2() {
        let keypair = KeypairJ::generate();
        assert_eq!(
            keypair.public,
            PublicKeyJ::from_private_key(keypair.private)
        );
    }

    #[test]
    fn test_keypairJ_from_private_key() {
        let private_key = Scalar::random(&mut OsRng);
        let keypair = KeypairJ::from_private_key(private_key);
        assert_eq!(keypair.public, PublicKeyJ::from_private_key(private_key));
        assert_eq!(keypair.private, private_key);
    }

    #[test]
    fn test_partial_signature_verification() {
        let nonce = Keypair::generate();
        let secret = Keypair::generate();
        let other_nonce = Keypair::generate().public;
        let other_secret = Keypair::generate().public;

        let public_nonces = nonce.public + other_nonce;
        let public_keys = secret.public + other_secret;

        let challenge = Signature::calculate_challenge(&public_nonces, &public_keys);
        let signature = Signature::new(&nonce, &secret.private, challenge);

        assert!(Signature::verify(&signature, &secret.public, challenge));
    }

    #[test]
    fn test_partial_generalised_signature_verification() {
        let secret_value = Keypair::generate();
        let blinding_factor = KeypairJ::generate();
        let other_secret = Keypair::generate();
        let other_factor = KeypairJ::generate();
        let nonce_1 = Keypair::generate();
        let nonce_2 = KeypairJ::generate();
        let other_nonce_1 = Keypair::generate();
        let other_nonce_2 = KeypairJ::generate();

        let R = commit_hj(
            nonce_1.private + other_nonce_1.private,
            nonce_2.private + other_nonce_2.private,
        );
        let C = commit_hj(
            blinding_factor.private + other_factor.private,
            secret_value.private + other_secret.private,
        );
        let challenge = GeneralisedSignature::calculate_challenge(&C, &R);
        let signature = GeneralisedSignature::new_excess_proof(
            &nonce_1,
            &nonce_2,
            &secret_value.private,
            &blinding_factor.private,
            challenge,
        );

        assert!(GeneralisedSignature::verify_excess_proof(
            &signature,
            secret_value.public.0 + blinding_factor.public.0,
            challenge
        ));
    }

    #[test]
    fn test_aggregated_signature() {
        let nonce1 = Keypair::generate();
        let nonce2 = Keypair::generate();
        let secret1 = Keypair::generate();
        let secret2 = Keypair::generate();

        let public_nonces = nonce1.public + nonce2.public;
        let public_keys = secret1.public + secret2.public;
        let challenge = Signature::calculate_challenge(&public_nonces, &public_keys);

        let sig1 = Signature::new(&nonce1, &secret1.private, challenge);
        let sig2 = Signature::new(&nonce2, &secret2.private, challenge);

        let aggregated_sig = Signature::aggregate(vec![&sig1, &sig2]);

        assert!(Signature::verify(&aggregated_sig, &public_keys, challenge));
    }

    #[test]
    fn test_aggregated_generasised_signature() {
        let secret_value = Keypair::generate();
        let blinding_factor = KeypairJ::generate();
        let other_secret = Keypair::generate();
        let other_factor = KeypairJ::generate();
        let nonce_1 = Keypair::generate();
        let nonce_2 = KeypairJ::generate();
        let other_nonce_1 = Keypair::generate();
        let other_nonce_2 = KeypairJ::generate();

        let R = commit_hj(
            nonce_1.private + other_nonce_1.private,
            nonce_2.private + other_nonce_2.private,
        );
        let C = commit_hj(
            blinding_factor.private + other_factor.private,
            secret_value.private + other_secret.private,
        );
        let challenge = GeneralisedSignature::calculate_challenge(&C, &R);

        let sig1 = GeneralisedSignature::new_excess_proof(
            &nonce_1,
            &nonce_2,
            &secret_value.private,
            &blinding_factor.private,
            challenge,
        );
        let sig2 = GeneralisedSignature::new_excess_proof(
            &nonce_1,
            &nonce_2,
            &other_secret.private,
            &other_factor.private,
            challenge,
        );

        let aggregated_sig = GeneralisedSignature::aggregate(vec![&sig1, &sig2]);
        let public_keys = secret_value.public.0
            + blinding_factor.public.0
            + other_secret.public.0
            + other_factor.public.0;

        assert!(GeneralisedSignature::verify_excess_proof(
            &aggregated_sig,
            public_keys,
            challenge
        ));
    }

    #[test]
    fn test_signature_verify_invalid() {
        // Generate the original message and key pairs
        let nonce = Keypair::generate();
        let secret = Keypair::generate();
        let other_nonce = Keypair::generate().public;
        let other_secret = Keypair::generate().public;

        let public_nonces = nonce.public + other_nonce;
        let public_keys = secret.public + other_secret;
        let challenge = Signature::calculate_challenge(&public_nonces, &public_keys);

        // Generate the original signature
        let signature = Signature::new(&nonce, &secret.private, challenge);

        // Modify the signature to make it invalid
        let invalid_signature = Signature {
            s: Scalar::zero(),
            R: signature.R,
        };

        // Modify the message to make it invalid
        let mut hasher = Hasher::new();
        hasher.update("tampered".as_bytes());
        hasher.update(public_nonces.0.compress().as_bytes());
        hasher.update(public_keys.0.compress().as_bytes());
        let tampered_message = Scalar::from_bytes_mod_order(*hasher.finalize().as_bytes());

        // Verify the original and modified signatures
        let valid = Signature::verify(&signature, &secret.public, challenge);
        let invalid1 = Signature::verify(&invalid_signature, &secret.public, challenge);
        let invalid2 = Signature::verify(&signature, &secret.public, tampered_message);

        // Assert the results
        assert!(valid);
        assert!(!invalid1);
        assert!(!invalid2);
    }

    #[test]
    fn test_input_proof_signature() {
        // GeneralisedSignature::new_input_proof
        let secret_value = Scalar::random(&mut rand::thread_rng());
        let blinding_factor = Scalar::random(&mut rand::thread_rng());

        let proof = GeneralisedSignature::new_input_proof(secret_value, blinding_factor);

        assert!(GeneralisedSignature::verify_input_proof(
            &proof,
            commit(secret_value, blinding_factor)
        ));
    }
}
