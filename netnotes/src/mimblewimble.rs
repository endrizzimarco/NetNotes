use super::pedersen;
use super::pedersen::Commitment;
use super::schnorr::{Keypair, PublicKey, Signature};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use uuid::Uuid;

pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    kernel: Kernel,
}

type Input = Commitment;
type Output = Commitment;

// struct Output {
//     commitment: Commitment,
//     // proof: RangeProof, TODO:
// }

struct Kernel {
    excess: PublicKey, // The pubkey of the below signature
    signature: Signature,
}

// === Intermedary transaction data ===
pub struct TxData {
    uuid: Uuid,
    inputs: Vec<Input>,
    amount: Scalar,
    change_output: Commitment,
    nonce_keypair: Keypair,
    blinding_keypair: Keypair,
}

pub struct SendData {
    uuid: Uuid,
    amount: Scalar,
    public_nonce: PublicKey,
    public_diff: PublicKey,
}

pub struct ResponseData {
    partial_sig: Signature,
    output_commitment: Commitment,
    nonce_commitment: PublicKey,
    blinding_commitment: PublicKey,
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
        println!("r_change: {:?}", r_output);
        let change_output: Commitment = pedersen::commit(change, r_output);

        // Calculate the difference between outputs' blinding factors and inputs' blinding factors
        let r_input = input_blinding_factors.iter().sum::<Scalar>();

        // Generate nonces to be used in Schnorr signature
        let nonce_keypair = Keypair::generate();

        // Generate blinding diff keypair
        let blinding_keypair = Keypair::from_private_key(r_output - r_input);

        TxData {
            uuid: Uuid::new_v4(),
            inputs,
            amount,
            change_output,
            nonce_keypair,
            blinding_keypair,
        }
    }

    // pub fn verify {} TODO:
}

impl TxData {
    pub fn send(&self) -> SendData {
        SendData {
            uuid: self.uuid,
            amount: self.amount,
            public_nonce: self.nonce_keypair.public,
            public_diff: self.blinding_keypair.public,
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
            &data.uuid,
            &(data.public_nonce + nonce_keypair.public),
            &(data.public_diff + blinding_keypair.public),
        );
        let partial_sig = Signature::new(&nonce_keypair, &blinding_keypair.private, challenge);

        ResponseData {
            partial_sig,
            output_commitment: pedersen::commit(data.amount, blinding_keypair.private),
            nonce_commitment: nonce_keypair.public,
            blinding_commitment: blinding_keypair.public,
        }
    }
}

impl ResponseData {
    /// The sender adds their half of the signature, aggregates the 2 partial signatures, and builds the final transaction.
    pub fn finalise(tx: &TxData, resp: &ResponseData) -> Transaction {
        let nonce_sum = tx.nonce_keypair.public + resp.nonce_commitment;
        let blinding_sum = tx.blinding_keypair.public + resp.blinding_commitment;

        let challenge = Signature::calculate_challenge(&tx.uuid, &nonce_sum, &blinding_sum);
        println!("Challenge: {:?}", challenge);
        let verify = Signature::verify(&resp.partial_sig, &resp.blinding_commitment, challenge);

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
                excess: tx.blinding_keypair.public + resp.blinding_commitment,
                signature,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // TODO: aswell as send and response tests + should fail when amount is wrong etc
    fn test_init_transaction() {
        // Arrange
        let amount = Scalar::from(100u64);
        let change = Scalar::from(20u64);
        let input_blinding_factors = vec![Scalar::from(10u64), Scalar::from(15u64)];
        let inputs = vec![
            pedersen::commit(Scalar::from(100u64), Scalar::from(10u64)),
            pedersen::commit(Scalar::from(100u64), Scalar::from(15u64)),
        ];

        // Act
        let tx_data = Transaction::init(amount, change, input_blinding_factors, inputs);

        // Assert
        assert_eq!(tx_data.amount, amount);
        // assert_eq!(tx_data.inputs, inputs);
    }

    #[test]
    fn test_finalise_transaction() {
        // mock tx data
        let r_output = Scalar::random(&mut OsRng);
        let r_input = Scalar::random(&mut OsRng);
        let tx_data = TxData {
            uuid: Uuid::new_v4(),
            inputs: vec![pedersen::commit(Scalar::from(150u64), r_input)],
            amount: Scalar::from(100u64),
            change_output: pedersen::commit(Scalar::from(50u64), r_output),
            nonce_keypair: Keypair::generate(),
            blinding_keypair: Keypair::from_private_key(Scalar::from(r_output - r_input)),
        };

        let other_nonce = Keypair::generate();
        let other_blinding = Keypair::from_private_key(Scalar::from(6u64));
        let output_commitment = pedersen::commit(Scalar::from(100u64), other_blinding.private);

        let challenge = Signature::calculate_challenge(
            &tx_data.uuid,
            &(tx_data.nonce_keypair.public + other_nonce.public),
            &(tx_data.blinding_keypair.public + other_blinding.public),
        );

        // mock response data
        let response_data = ResponseData {
            partial_sig: Signature::new(&other_nonce, &other_blinding.private, challenge),
            output_commitment,
            nonce_commitment: other_nonce.public,
            blinding_commitment: other_blinding.public,
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
        assert_kernel(transaction, challenge);
    }

    #[test]
    // Similar to above, but does not mock data
    fn test_transaction() {
        // Initialize inputs and blinding factors
        let blinding_1 = Scalar::random(&mut OsRng);
        let blinding_2 = Scalar::random(&mut OsRng);
        let input_blinding_factors = vec![blinding_1, blinding_2];
        let inputs = vec![
            pedersen::commit(Scalar::from(10u64), blinding_1),
            pedersen::commit(Scalar::from(20u64), blinding_2),
        ];

        // Initialize a transaction
        let tx_data = Transaction::init(
            Scalar::from(25u64),
            Scalar::from(5u64),
            input_blinding_factors,
            inputs.clone(),
        );

        let send_data = tx_data.send();
        let response_data = SendData::respond(&send_data);
        let transaction = ResponseData::finalise(&tx_data, &response_data);
        let challenge = Signature::calculate_challenge(
            &tx_data.uuid,
            &(tx_data.nonce_keypair.public + response_data.nonce_commitment),
            &(tx_data.blinding_keypair.public + response_data.blinding_commitment),
        );

        assert_eq!(transaction.inputs, tx_data.inputs);
        assert_eq!(transaction.outputs.len(), 2);
        assert_eq!(transaction.outputs[0], tx_data.change_output);
        assert_eq!(transaction.outputs[1], response_data.output_commitment);
        assert_eq!(
            transaction.kernel.excess,
            tx_data.blinding_keypair.public + response_data.blinding_commitment
        );
        assert_kernel(transaction, challenge);
    }

    #[test]
    fn test_point_addition() {
        // Test the sum() function for point addition
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

    fn assert_kernel(transaction: Transaction, challenge: Scalar) {
        // Check if the transaction kernel is valid
        let kernel = &transaction.kernel;
        let excess = kernel.excess;
        let signature = &kernel.signature;

        // get outputs - inputs
        let (inputs_sum, outputs_sum) = sum_commitments(&transaction);
        let expected_excess = PublicKey(outputs_sum - inputs_sum);
        assert_eq!(expected_excess, excess);

        let verify_kernel_excess = Signature::verify(signature, &excess, challenge);
        let verify_expected_excess = Signature::verify(signature, &expected_excess, challenge);

        assert_eq!(verify_kernel_excess, true);
        assert_eq!(verify_expected_excess, true);
    }

    fn sum_commitments(transaction: &Transaction) -> (RistrettoPoint, RistrettoPoint) {
        // sum inputs
        let input_sum = transaction
            .inputs
            .iter()
            .fold(None, |acc, p| match acc {
                None => Some(*p),
                Some(q) => Some(q + p),
            })
            .unwrap();

        // sum outputs
        let output_sum = transaction
            .outputs
            .iter()
            .fold(None, |acc, p| match acc {
                None => Some(*p),
                Some(q) => Some(q + p),
            })
            .unwrap();
        (input_sum, output_sum)
    }
}
