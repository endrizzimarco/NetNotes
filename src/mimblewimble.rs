use super::pedersen::{Commitment, GENS};
use super::schnorr::{Keypair, PublicKey, Signature};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    kernel: Kernel,
}

type Input = Commitment;
type Output = Commitment;

pub struct Kernel {
    excess: PublicKey, // The pubkey of the below signature
    signature: Signature,
}

// === Intermedary transaction data ===
pub struct TxData {
    inputs: Vec<Input>,
    amount: Scalar,
    change_output: Commitment,
    nonce_keypair: Keypair,
    blinding_keypair: Keypair,
}

pub struct SendData {
    amount: Scalar,
    public_nonce: PublicKey,
    public_blinding_diff: PublicKey,
}

pub struct ResponseData {
    partial_sig: Signature,
    output_commitment: Commitment,
    public_nonce: PublicKey,
    public_blinding: PublicKey,
}

trait PointAddition {
    fn sum(&self) -> Option<RistrettoPoint>;
}

impl PointAddition for Vec<RistrettoPoint> {
    fn sum(&self) -> Option<RistrettoPoint> {
        self.iter().fold(None, |acc, p| match acc {
            None => Some(*p),
            Some(q) => Some(q + p),
        })
    }
}

impl Transaction {
    /// Sender commits to amount, fee, and a public nonce, public excess.
    /// It could also commit to tx offset, inputs, change output, and probably others.
    pub fn init(
        amount: Scalar,
        change: Scalar,
        input_blinding_factors: Vec<Scalar>,
        inputs: Vec<Input>,
    ) -> TxData {
        // Generate change_output
        let r_output = Scalar::random(&mut OsRng);
        let change_output: Commitment = GENS.commit(change, r_output);

        // Calculate the difference between outputs' blinding factors and inputs' blinding factors
        let r_input = input_blinding_factors.iter().sum::<Scalar>();

        // Generate nonces to be used in Schnorr signature
        let nonce_keypair = Keypair::generate();

        // Generate blinding diff keypair
        let blinding_keypair = Keypair::from_private_key(r_output - r_input);

        TxData {
            inputs,
            amount,
            change_output,
            nonce_keypair,
            blinding_keypair,
        }
    }

    pub fn verify(&self) -> bool {
        // Check if the transaction kernel is valid
        let kernel = &self.kernel;
        let excess = kernel.excess;
        let signature = &kernel.signature;

        let challenge = Signature::calculate_challenge(&signature.R, &excess);

        // get outputs - inputs
        let expected_excess = PublicKey(
            self.outputs.iter().sum::<RistrettoPoint>()
                - self.inputs.iter().sum::<RistrettoPoint>(),
        );

        let verify_kernel_excess = Signature::verify(signature, &excess, challenge);
        let verify_expected_excess = Signature::verify(signature, &expected_excess, challenge);

        (expected_excess == excess) && verify_kernel_excess && verify_expected_excess
    }
}

impl TxData {
    pub fn send(&self) -> SendData {
        SendData {
            amount: self.amount,
            public_nonce: self.nonce_keypair.public,
            public_blinding_diff: self.blinding_keypair.public,
        }
    }
}

impl SendData {
    /// The receiver adds their output & rangeproof, and commits to their public nonce and excess.
    /// It then updates the total kernel commitment, and signs for their half of the kernel.
    pub fn respond(data: &SendData) -> ResponseData {
        let nonce_keypair = Keypair::generate();
        let blinding_keypair = Keypair::generate();

        let challenge = Signature::calculate_challenge(
            &(data.public_nonce + nonce_keypair.public),
            &(data.public_blinding_diff + blinding_keypair.public),
        );
        let partial_sig = Signature::new(&nonce_keypair, &blinding_keypair.private, challenge);

        ResponseData {
            partial_sig,
            output_commitment: GENS.commit(data.amount, blinding_keypair.private),
            public_nonce: nonce_keypair.public,
            public_blinding: blinding_keypair.public,
        }
    }
}

impl ResponseData {
    /// The sender adds their half of the signature, aggregates the 2 partial signatures, and builds the final transaction.
    pub fn finalise(tx: &TxData, resp: &ResponseData) -> Transaction {
        let nonce_sum = tx.nonce_keypair.public + resp.public_nonce;
        let blinding_sum = tx.blinding_keypair.public + resp.public_blinding;

        let challenge = Signature::calculate_challenge(&nonce_sum, &blinding_sum);
        let verify = Signature::verify(&resp.partial_sig, &resp.public_blinding, challenge);

        if verify == false {
            panic!("Signature verification failed");
        }

        let partial_sig =
            Signature::new(&tx.nonce_keypair, &tx.blinding_keypair.private, challenge);
        let signature = Signature::aggregate(vec![&partial_sig, &resp.partial_sig]);

        Transaction {
            inputs: tx.inputs.clone(),
            outputs: vec![tx.change_output, resp.output_commitment],
            kernel: Kernel {
                excess: blinding_sum,
                signature,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_transaction() {
        // Arrange
        let amount = Scalar::from(100u64);
        let change = Scalar::from(20u64);
        let input_blinding_factors = vec![Scalar::from(10u64), Scalar::from(15u64)];
        let inputs = vec![
            GENS.commit(Scalar::from(100u64), Scalar::from(10u64)),
            GENS.commit(Scalar::from(100u64), Scalar::from(15u64)),
        ];
        let tx_data = Transaction::init(amount, change, input_blinding_factors, inputs);

        // Act
        let send_data = tx_data.send();

        // Assert
        assert_eq!(send_data.amount, amount);
        assert_eq!(
            send_data.public_blinding_diff,
            tx_data.blinding_keypair.public
        );
        assert_eq!(send_data.public_nonce, tx_data.nonce_keypair.public);
    }

    #[test]
    fn test_finalise_transaction() {
        // mock tx data
        let r_output = Scalar::random(&mut OsRng);
        let r_input = Scalar::random(&mut OsRng);
        let tx_data = TxData {
            inputs: vec![GENS.commit(Scalar::from(150u64), r_input)],
            amount: Scalar::from(100u64),
            change_output: GENS.commit(Scalar::from(50u64), r_output),
            nonce_keypair: Keypair::generate(),
            blinding_keypair: Keypair::from_private_key(Scalar::from(r_output - r_input)),
        };

        let other_nonce = Keypair::generate();
        let other_blinding = Keypair::from_private_key(Scalar::from(6u64));
        let output_commitment = GENS.commit(Scalar::from(100u64), other_blinding.private);

        let challenge = Signature::calculate_challenge(
            &(tx_data.nonce_keypair.public + other_nonce.public),
            &(tx_data.blinding_keypair.public + other_blinding.public),
        );

        // mock response data
        let response_data = ResponseData {
            partial_sig: Signature::new(&other_nonce, &other_blinding.private, challenge),
            output_commitment,
            public_nonce: other_nonce.public,
            public_blinding: other_blinding.public,
        };

        // Act
        let transaction = ResponseData::finalise(&tx_data, &response_data);

        // Assert
        assert_eq!(transaction.inputs, tx_data.inputs);
        assert_eq!(transaction.outputs.len(), 2);
        assert_eq!(transaction.outputs[0], tx_data.change_output);
        assert_eq!(transaction.outputs[1], response_data.output_commitment);
        assert_eq!(
            transaction.kernel.excess,
            tx_data.blinding_keypair.public + other_blinding.public
        );
        assert!(transaction.verify());
    }

    #[test]
    #[should_panic(expected = "Signature verification failed")]
    fn test_incorrect_response() {
        // mock tx data
        let tx_data = TxData {
            inputs: vec![GENS.commit(Scalar::from(150u64), Scalar::from(10u64))],
            amount: Scalar::from(100u64),
            change_output: GENS.commit(Scalar::from(50u64), Scalar::from(5u64)),
            nonce_keypair: Keypair::generate(),
            blinding_keypair: Keypair::from_private_key(Scalar::from(5u64)),
        };

        let other_nonce = Keypair::generate();
        let other_blinding = Keypair::from_private_key(Scalar::from(6u64));
        let output_commitment = GENS.commit(Scalar::from(100u64), other_blinding.private);

        let challenge = Signature::calculate_challenge(
            &(tx_data.nonce_keypair.public + other_nonce.public),
            &(tx_data.blinding_keypair.public + other_blinding.public),
        );

        // mock response data
        let response_data = ResponseData {
            partial_sig: Signature::new(&other_nonce, &other_nonce.private, challenge),
            output_commitment,
            public_nonce: other_nonce.public,
            public_blinding: other_blinding.public,
        };

        // Act
        ResponseData::finalise(&tx_data, &response_data);
    }

    #[test]
    fn test_correct_transaction() {
        let ten = Scalar::from(10u64);
        let keypair = &Keypair::from_private_key(ten);
        let challenge =
            Signature::calculate_challenge(&keypair.public, &PublicKey::from_private_key(ten));
        let signature = Signature::new(keypair, &ten, challenge);

        let transaction = Transaction {
            inputs: vec![GENS.commit(Scalar::from(150u64), ten)],
            outputs: vec![
                GENS.commit(Scalar::from(50u64), ten),
                GENS.commit(Scalar::from(100u64), ten),
            ],
            kernel: Kernel {
                excess: PublicKey::from_private_key(ten),
                signature,
            },
        };

        assert!(transaction.verify());
    }

    #[test]
    // wrong amount
    fn test_incorrect_transaction_1() {
        let ten = Scalar::from(10u64);
        let keypair = &Keypair::from_private_key(ten);
        let challenge =
            Signature::calculate_challenge(&keypair.public, &PublicKey::from_private_key(ten));
        let signature = Signature::new(keypair, &ten, challenge);

        let transaction = Transaction {
            inputs: vec![GENS.commit(Scalar::from(150u64), ten)],
            outputs: vec![GENS.commit(Scalar::from(1000u64), ten)],
            kernel: Kernel {
                excess: PublicKey::from_private_key(ten),
                signature,
            },
        };

        assert!(!transaction.verify());
    }

    #[test]
    // wrong signature
    fn test_incorrect_transaction_2() {
        let ten = Scalar::from(10u64);
        let keypair = &Keypair::from_private_key(ten);
        let challenge = Signature::calculate_challenge(
            &keypair.public,
            &PublicKey::from_private_key(Scalar::one()),
        );
        let signature = Signature::new(keypair, &ten, challenge);

        let transaction = Transaction {
            inputs: vec![GENS.commit(Scalar::from(150u64), ten)],
            outputs: vec![GENS.commit(Scalar::from(1000u64), ten)],
            kernel: Kernel {
                excess: PublicKey::from_private_key(ten),
                signature,
            },
        };

        assert!(!transaction.verify());
    }

    #[test]
    // Test the sum() function for point addition
    fn test_point_addition() {
        let points = vec![
            RistrettoPoint::random(&mut OsRng),
            RistrettoPoint::random(&mut OsRng),
            RistrettoPoint::random(&mut OsRng),
        ];
        let sum = points
            .iter()
            .fold(RistrettoPoint::default(), |acc, p| acc + p);

        assert_eq!(points.sum().unwrap(), sum);
    }
}
