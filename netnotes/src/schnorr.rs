#![allow(non_snake_case)]

use blake3::Hasher;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use uuid::Uuid;

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct PublicKey(RistrettoPoint);

pub type PrivateKey = Scalar;

pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

#[derive(PartialEq, Debug, Clone, Copy)]
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
    pub fn new(
        message: Uuid,
        nonce: &Keypair,
        blinding_factor: &Keypair,
        other_nonce: &PublicKey,
        other_blinding_factor: PublicKey,
    ) -> Self {
        let nonce_sum = nonce.public.0 + other_nonce.0;
        let blinding_factor_sum = blinding_factor.public.0 + other_blinding_factor.0;
        let challenge = Self::challenge(message, nonce_sum, blinding_factor_sum);
        let signature = nonce.private + challenge * blinding_factor.private;

        Signature {
            s: signature,
            R: nonce.public,
        }
    }

    pub fn aggregate(partial_sigs: Vec<Signature>) -> Self {
        let (s, R) = partial_sigs.iter().fold(
            (Scalar::zero(), PublicKey::from_private_key(Scalar::zero())),
            |acc, sig| (acc.0 + sig.s, acc.1 + sig.R),
        );

        Signature { s, R }
    }

    pub fn verify(
        signature: &Signature,
        message: Uuid,
        public_key: &PublicKey,
        nonce_sum: PublicKey,
        blinding_factor_sum: PublicKey,
    ) -> bool {
        let e = Self::challenge(message, nonce_sum.0, blinding_factor_sum.0);
        let sG = PublicKey::from_private_key(signature.s);
        let R = signature.R;

        sG.0 == R.0 + e * public_key.0 // s.G == R + e.P
    }

    fn challenge(
        message: Uuid,
        public_nonces: RistrettoPoint,
        public_blinding_factors: RistrettoPoint,
    ) -> Scalar {
        let mut hasher = Hasher::new();
        hasher.update(message.as_bytes());
        hasher.update(public_nonces.compress().as_bytes());
        hasher.update(public_blinding_factors.compress().as_bytes());

        Scalar::from_bytes_mod_order(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::Pedersen;

    #[test]
    fn test_keypair_generation_1() {
        let keypair = Keypair::generate();
        // Verify that the public key can be reconstructed from the private key
        let expected_public_key = PublicKey(Pedersen::commit_unblinded(keypair.private));
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
        let blinding_factor = Keypair::generate();
        let other_nonce = Keypair::generate().public;
        let other_blinding_factor = Keypair::generate().public;

        let signature = Signature::new(
            message,
            &nonce,
            &blinding_factor,
            &other_nonce,
            other_blinding_factor,
        );

        assert!(Signature::verify(
            &signature,
            message,
            &blinding_factor.public,
            nonce.public + other_nonce,
            blinding_factor.public + other_blinding_factor,
        ));
    }

    #[test]
    fn test_aggregated_signature_verification() {
        let message = Uuid::new_v4();
        let nonce1 = Keypair::generate();
        let nonce2 = Keypair::generate();
        let blinding_factor1 = Keypair::generate();
        let blinding_factor2 = Keypair::generate();

        let sig1 = Signature::new(
            message,
            &nonce1,
            &blinding_factor1,
            &nonce2.public,
            blinding_factor2.public,
        );
        let sig2 = Signature::new(
            message,
            &nonce2,
            &blinding_factor2,
            &nonce1.public,
            blinding_factor1.public,
        );

        let aggregated_sig = Signature::aggregate(vec![sig1, sig2]);
        let public_key_sum = blinding_factor1.public + blinding_factor2.public;

        assert!(Signature::verify(
            &aggregated_sig,
            message,
            &public_key_sum,
            nonce1.public + nonce2.public,
            blinding_factor1.public + blinding_factor2.public,
        ));
    }

    #[test]
    // TODO: should nonce be generated from within??
    fn test_signature_new() {
        let message1 = Uuid::new_v4();
        let message2 = Uuid::new_v4();
        let nonce1 = Keypair::generate();
        let nonce2 = Keypair::generate();
        let blinding_factor1 = Keypair::generate();
        let blinding_factor2 = Keypair::generate();
        let other_nonce = PublicKey::from_private_key(Scalar::zero());
        let other_blinding_factor = PublicKey::from_private_key(Scalar::zero());

        let signature1 = Signature::new(
            message1,
            &nonce1,
            &blinding_factor1,
            &other_nonce,
            other_blinding_factor,
        );
        let signature2 = Signature::new(
            message2,
            &nonce2,
            &blinding_factor2,
            &other_nonce,
            other_blinding_factor,
        );

        assert_ne!(
            signature1,
            Signature::new(
                message1,
                &Keypair::generate(),
                &blinding_factor1,
                &other_nonce,
                other_blinding_factor
            )
        );
        assert_ne!(signature1, signature2);
        assert_ne!(
            signature2,
            Signature::new(
                message2,
                &Keypair::generate(),
                &blinding_factor2,
                &other_nonce,
                other_blinding_factor
            )
        );
    }

    #[test]
    fn test_signature_verify_invalid() {
        let message = Uuid::new_v4();
        let nonce = Keypair::generate();
        let blinding_factor = Keypair::generate();
        let other_nonce = Keypair::generate().public;
        let other_blinding_factor = Keypair::generate().public;

        let signature = Signature::new(
            message,
            &nonce,
            &blinding_factor,
            &other_nonce,
            other_blinding_factor,
        );

        // Modify the signature to make it invalid
        let invalid_signature = Signature {
            s: Scalar::zero(),
            R: signature.R,
        };

        // Modify the message to make it invalid
        let tampered_message = Uuid::new_v4();

        let valid = Signature::verify(
            &signature,
            message,
            &blinding_factor.public,
            nonce.public + other_nonce,
            blinding_factor.public + other_blinding_factor,
        );
        let invalid1 = Signature::verify(
            &invalid_signature,
            message,
            &signature.R,
            nonce.public + other_nonce,
            blinding_factor.public + other_blinding_factor,
        );
        let invalid2 = Signature::verify(
            &signature,
            tampered_message,
            &signature.R,
            nonce.public + other_nonce,
            blinding_factor.public + other_blinding_factor,
        );

        assert!(valid);
        assert!(!invalid1);
        assert!(!invalid2);
    }
}
