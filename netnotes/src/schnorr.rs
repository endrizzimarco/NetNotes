#![allow(non_snake_case)]
use blake3::Hasher;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use uuid::Uuid;

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct PublicKey(pub RistrettoPoint);

pub type PrivateKey = Scalar;

pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

#[derive(PartialEq, Debug)]
pub struct Signature {
    s: Scalar,
    R: PublicKey,
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

impl PublicKey {
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        PublicKey(&private_key * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl std::ops::Add for PublicKey {
    type Output = PublicKey;

    fn add(self, other: PublicKey) -> PublicKey {
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

    pub fn calculate_challenge(
        message: &Uuid,
        public_nonces: &PublicKey,
        public_keys: &PublicKey,
    ) -> Scalar {
        let mut hasher = Hasher::new();
        hasher.update(message.as_bytes());
        hasher.update(public_nonces.0.compress().as_bytes());
        hasher.update(public_keys.0.compress().as_bytes());

        Scalar::from_bytes_mod_order(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen;

    #[test]
    fn test_keypair_generation_1() {
        let keypair = Keypair::generate();
        // Verify that the public key can be reconstructed from the private key
        let expected_public_key = PublicKey(pedersen::commit_unblinded(keypair.private));
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
    fn test_single_signature_verification() {
        let message = Uuid::new_v4();
        let nonce = Keypair::generate();
        let secret = Keypair::generate();
        let other_nonce = Keypair::generate().public;
        let other_secret = Keypair::generate().public;

        let public_nonces = nonce.public + other_nonce;
        let public_keys = secret.public + other_secret;

        let challenge = Signature::calculate_challenge(&message, &public_nonces, &public_keys);
        let signature = Signature::new(&nonce, &secret.private, challenge);

        assert!(Signature::verify(&signature, &secret.public, challenge));
    }

    #[test]
    fn test_aggregated_signature_verification() {
        let message = Uuid::new_v4();
        let nonce1 = Keypair::generate();
        let nonce2 = Keypair::generate();
        let secret1 = Keypair::generate();
        let secret2 = Keypair::generate();

        let public_nonces = nonce1.public + nonce2.public;
        let public_keys = secret1.public + secret2.public;
        let challenge = Signature::calculate_challenge(&message, &public_nonces, &public_keys);

        let sig1 = Signature::new(&nonce1, &secret1.private, challenge);
        let sig2 = Signature::new(&nonce2, &secret2.private, challenge);

        let aggregated_sig = Signature::aggregate(vec![&sig1, &sig2]);

        assert!(Signature::verify(&aggregated_sig, &public_keys, challenge));
    }

    #[test]
    fn test_signature_verify_invalid() {
        // Generate the original message and key pairs
        let message = Uuid::new_v4();
        let nonce = Keypair::generate();
        let secret = Keypair::generate();
        let other_nonce = Keypair::generate().public;
        let other_secret = Keypair::generate().public;

        let public_nonces = nonce.public + other_nonce;
        let public_keys = secret.public + other_secret;
        let challenge = Signature::calculate_challenge(&message, &public_nonces, &public_keys);

        // Generate the original signature
        let signature = Signature::new(&nonce, &secret.private, challenge);

        // Modify the signature to make it invalid
        let invalid_signature = Signature {
            s: Scalar::zero(),
            R: signature.R,
        };

        // Modify the message to make it invalid
        let tampered_message =
            Signature::calculate_challenge(&Uuid::new_v4(), &public_nonces, &public_keys);

        // Verify the original and modified signatures
        let valid = Signature::verify(&signature, &secret.public, challenge);
        let invalid1 = Signature::verify(&invalid_signature, &secret.public, challenge);
        let invalid2 = Signature::verify(&signature, &secret.public, tampered_message);

        // Assert the results
        assert!(valid);
        assert!(!invalid1);
        assert!(!invalid2);
    }
}
