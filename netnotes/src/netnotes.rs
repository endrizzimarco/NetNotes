#![allow(non_snake_case)]
use super::pedersen;
use super::pedersen::{Commitment, GeneralisedCommitment, GENS};
use super::schnorr::{GeneralisedSignature, Keypair, KeypairH, PublicKey, PublicKeyH};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use one_of_many_proofs::proofs::{OneOfManyProof, OneOfManyProofs};
use rand::rngs::OsRng;

type Input = Commitment;
type Output = GeneralisedCommitment;

pub struct Transaction {
    inputs: Vec<Input>,
    schnorr_proofs: Vec<GeneralisedSignature>,
    ooom_proofs: Vec<OneOfManyProof>,
    outputs: Vec<Output>,
    kernel: Kernel,
}

pub struct Kernel {
    excess: GeneralisedCommitment, // The pubkey of the below signature
    signature: GeneralisedSignature,
}

// Data initialised and stored by sender to later form a transaction
pub struct TxData {
    inputs: Vec<Input>,
    schnorr_proofs: Vec<GeneralisedSignature>,
    ooom_proofs: Vec<OneOfManyProof>,
    amount: Scalar,
    change_output: GeneralisedCommitment,
    nonces_commitment: Commitment,
    excess_commitment: Commitment,
    output_blindings: (Scalar, Scalar),
    schnorr_nonces: (Keypair, KeypairH),
}

// Data sent to receiver
pub struct SendData {
    amount: Scalar,
    nonces_commitment: Commitment,
    excess_commitment: Commitment,
}

// Data received by sender
pub struct ResponseData {
    partial_sig: GeneralisedSignature,
    output_commitment: GeneralisedCommitment,
    public_nonces: (PublicKey, PublicKeyH),
    public_blinding: (PublicKey, PublicKeyH),
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
        inputs_values: Vec<Scalar>,
        inputs_blinding_r: Vec<Scalar>,
        inputs_blinding_s: Vec<Scalar>,
        stxo_positions: Vec<usize>,
        stxo_set: Vec<GeneralisedCommitment>,
    ) -> TxData {
        // Generate inputs by committing to the value and blinding factor
        let inputs: Vec<Commitment> = inputs_values
            .iter()
            .zip(inputs_blinding_r.iter())
            .map(|(v, r)| pedersen::commit_hj(*r, *v))
            .collect();

        // Generate Schnorr nonces
        let nonce_G = Keypair::generate();
        let nonce_H = KeypairH::generate();
        // Generate blinding factors for change output
        let r_output = Scalar::random(&mut OsRng);
        let s_output = Scalar::random(&mut OsRng);

        // Generate the senders' output commitment (change)
        let change_output: Commitment = pedersen::generalised_commit(change, r_output, s_output);

        // Calculate commitments to send to receiver for generating partial signature
        let blinding_diff = r_output - inputs_blinding_r.iter().sum::<Scalar>();
        let nonces_commitment = (nonce_G.public + nonce_H.public).0;
        let excess_commitment = pedersen::commit(blinding_diff, s_output);

        // Generate schnorr proofs for every input proving the commitment is in the form r.H + v.J
        let schnorr_proofs = Self::generate_schnorr_proofs(inputs_values, inputs_blinding_r);

        // Generate ooom proofs for every input proving the knowledge of the openings of a commitment in the STXO set
        let ooom_proofs =
            Self::generate_ooom_proofs(stxo_set, stxo_positions, &inputs, inputs_blinding_s);

        TxData {
            inputs,
            amount,
            schnorr_proofs,
            ooom_proofs,
            change_output,
            nonces_commitment,
            excess_commitment,
            output_blindings: (blinding_diff, s_output),
            schnorr_nonces: (nonce_G, nonce_H),
        }
    }

    pub fn verify(&self, stxo_set: Vec<GeneralisedCommitment>) -> bool {
        let excess = self.kernel.excess;
        let signature = &self.kernel.signature;

        // manually calculate the expected excess (sum of outputs - sum of inputs)
        let expected_excess = self.outputs.iter().sum::<RistrettoPoint>()
            - self.inputs.iter().sum::<RistrettoPoint>();

        // check signature against provided and calculated excess
        let challenge = GeneralisedSignature::calculate_challenge(&excess, &signature.R.0);
        let verify_kernel_excess =
            GeneralisedSignature::verify_excess_proof(signature, excess, challenge);
        let verify_expected_kernel = expected_excess == excess;

        // verify schnorr, ooom (validity/ownership of inputs) and kernel proofs (no money created or destroyed)
        self.verify_schnorr_proofs()
            && self.verify_ooom_proofs(stxo_set)
            && verify_expected_kernel
            && verify_kernel_excess
    }

    fn generate_schnorr_proofs(
        inputs_value: Vec<Scalar>,
        inputs_blinding_factor: Vec<Scalar>,
    ) -> Vec<GeneralisedSignature> {
        inputs_value
            .iter()
            .zip(inputs_blinding_factor.iter())
            .map(|(v, r)| GeneralisedSignature::new_input_proof(*v, *r))
            .collect()
    }

    // Verify that every input commitment is in the form v.G + r.H
    fn verify_schnorr_proofs(&self) -> bool {
        self.inputs
            .iter()
            .zip(self.schnorr_proofs.iter())
            .all(|(input, proof)| proof.verify_input_proof(input))
    }

    fn generate_ooom_proofs(
        mut stxo_set: Vec<GeneralisedCommitment>,
        pos: Vec<usize>,
        inputs: &Vec<Commitment>,
        blinding_factor_s: Vec<Scalar>,
    ) -> Vec<OneOfManyProof> {
        pos.iter()
            .zip(inputs.iter())
            .zip(blinding_factor_s.iter())
            .map(|((pos, input), blinding_factor_s)| {
                // subtract the input from every element in the stxo set
                stxo_set.iter_mut().for_each(|stxo| *stxo = *stxo - input);
                stxo_set
                    .iter()
                    .prove(
                        &GENS,
                        &mut Transcript::new(b"OneOfMany"),
                        *pos,
                        &blinding_factor_s,
                    )
                    .unwrap()
            })
            .collect()
    }

    // Verify that every input commitment is stored in the STXO set
    fn verify_ooom_proofs(&self, stxo_set: Vec<GeneralisedCommitment>) -> bool {
        self.inputs
            .iter()
            .zip(self.ooom_proofs.iter())
            .all(|(input, proof)| {
                let mut stxo_set = stxo_set.clone();
                stxo_set.iter_mut().for_each(|stxo| *stxo = *stxo - input);
                stxo_set
                    .iter()
                    .verify(&GENS, &mut Transcript::new(b"OneOfMany"), &proof)
                    .is_ok()
            })
    }
}

impl TxData {
    pub fn send(&self) -> SendData {
        SendData {
            amount: self.amount,
            nonces_commitment: self.nonces_commitment,
            excess_commitment: self.excess_commitment,
        }
    }
}

impl SendData {
    /// The receiver adds their output & rangeproof, and commits to their public nonce and excess.
    /// It then updates the total kernel commitment, and signs for their half of the kernel.
    pub fn respond(data: &SendData) -> ResponseData {
        // Generate blinding factors for output
        let s_keypair = Keypair::generate();
        let r_keypair = KeypairH::generate();
        // Generate Schnorr nonces
        let nonce_G = Keypair::generate();
        let nonce_H = KeypairH::generate();

        let output_commitment: GeneralisedCommitment =
            pedersen::generalised_commit(data.amount, r_keypair.private, s_keypair.private);

        let excess_commitment = (s_keypair.public + r_keypair.public).0;
        let nonces_commitment = (nonce_G.public + nonce_H.public).0;

        let challenge = GeneralisedSignature::calculate_challenge(
            &(excess_commitment + data.excess_commitment),
            &(nonces_commitment + data.nonces_commitment),
        );

        let partial_sig = GeneralisedSignature::new_excess_proof(
            &nonce_G,
            &nonce_H,
            &s_keypair.private,
            &r_keypair.private,
            challenge,
        );

        ResponseData {
            partial_sig,
            output_commitment,
            public_nonces: (nonce_G.public, nonce_H.public),
            public_blinding: (s_keypair.public, r_keypair.public),
        }
    }
}

impl ResponseData {
    /// The sender adds their half of the signature, aggregates the 2 partial signatures, and builds the final transaction.
    pub fn finalise(tx: TxData, resp: &ResponseData) -> Transaction {
        let blinding_commitment = resp.public_blinding.0 + resp.public_blinding.1;
        let nonces_commitment = resp.public_nonces.0 + resp.public_nonces.1;
        // get the final nonce and excess for the transaction
        let final_nonce = tx.nonces_commitment + nonces_commitment.0;
        let excess = tx.excess_commitment + blinding_commitment.0;

        let challenge = GeneralisedSignature::calculate_challenge(&excess, &final_nonce);
        let verify = resp
            .partial_sig
            .verify_excess_proof(blinding_commitment.0, challenge);

        if verify == false {
            panic!("Signature verification failed");
        }

        let partial_sig = GeneralisedSignature::new_excess_proof(
            &tx.schnorr_nonces.0,
            &tx.schnorr_nonces.1,
            &tx.output_blindings.0,
            &tx.output_blindings.1,
            challenge,
        );
        let signature = GeneralisedSignature::aggregate(vec![&partial_sig, &resp.partial_sig]);

        Transaction {
            inputs: tx.inputs,
            schnorr_proofs: tx.schnorr_proofs,
            ooom_proofs: tx.ooom_proofs,
            outputs: vec![tx.change_output, resp.output_commitment],
            kernel: Kernel { excess, signature },
        }
    }
}

// #[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_proofs() {
        let (amount, change, inputs_values, inputs_blinding_r, inputs_blinding_s, pos, stxo_set) =
            common_transaction_setup();

        let tx_data = Transaction::init(
            amount,
            change,
            inputs_values,
            inputs_blinding_r,
            inputs_blinding_s,
            pos,
            stxo_set,
        );

        let transaction = mock_tx(tx_data);
        assert!(transaction.verify_schnorr_proofs());
    }

    #[test]
    fn test_invalid_schnorr_proofs() {
        let (amount, change, inputs_values, inputs_blinding_r, inputs_blinding_s, pos, stxo_set) =
            common_transaction_setup();

        let tx_data = Transaction::init(
            amount,
            change,
            inputs_values,
            inputs_blinding_r,
            inputs_blinding_s,
            pos,
            stxo_set,
        );

        let mut transaction = mock_tx(tx_data);
        // Add a second blinding factor to the first input
        transaction.inputs[0] = pedersen::generalised_commit(
            Scalar::from(120u64),
            Scalar::from(10u64),
            Scalar::from(1u64),
        );
        assert!(!transaction.verify_schnorr_proofs())
    }

    #[test]
    fn test_valid_ooom_proofs() {
        let (amount, change, inputs_values, inputs_blinding_r, inputs_blinding_s, pos, stxo_set) =
            common_transaction_setup();

        let tx_data = Transaction::init(
            amount,
            change,
            inputs_values,
            inputs_blinding_r,
            inputs_blinding_s,
            pos,
            stxo_set.clone(),
        );

        let transaction = mock_tx(tx_data);
        assert!(transaction.verify_ooom_proofs(stxo_set));
    }

    // #[test]
    // fn test_send_transaction() {
    //     // Arrange
    //     let amount = Scalar::from(100u64);
    //     let change = Scalar::from(20u64);
    //     let input_blinding_factors = vec![Scalar::from(10u64), Scalar::from(15u64)];
    //     let inputs = vec![
    //         pedersen::commit(Scalar::from(100u64), Scalar::from(10u64)),
    //         pedersen::commit(Scalar::from(100u64), Scalar::from(15u64)),
    //     ];
    //     let tx_data = Transaction::init(amount, change, input_blinding_factors, inputs);

    //     // Act
    //     let send_data = tx_data.send();

    //     // Assert
    //     assert_eq!(send_data.amount, amount);
    //     assert_eq!(
    //         send_data.public_blinding_diff,
    //         tx_data.blinding_keypair.public
    //     );
    //     assert_eq!(send_data.public_nonce, tx_data.nonce_keypair.public);
    // }

    // #[test]
    // fn test_finalise_transaction() {
    //     // mock tx data
    //     let r_output = Scalar::random(&mut OsRng);
    //     let r_input = Scalar::random(&mut OsRng);
    //     let tx_data = TxData {
    //         inputs: vec![pedersen::commit(Scalar::from(150u64), r_input)],
    //         amount: Scalar::from(100u64),
    //         change_output: pedersen::commit(Scalar::from(50u64), r_output),
    //         nonce_keypair: Keypair::generate(),
    //         blinding_keypair: Keypair::from_private_key(Scalar::from(r_output - r_input)),
    //     };

    //     let other_nonce = Keypair::generate();
    //     let other_blinding = Keypair::from_private_key(Scalar::from(6u64));
    //     let output_commitment = pedersen::commit(Scalar::from(100u64), other_blinding.private);

    //     let challenge = Signature::calculate_challenge(
    //         &(tx_data.nonce_keypair.public + other_nonce.public),
    //         &(tx_data.blinding_keypair.public + other_blinding.public),
    //     );

    //     // mock response data
    //     let response_data = ResponseData {
    //         partial_sig: Signature::new(&other_nonce, &other_blinding.private, challenge),
    //         output_commitment,
    //         public_nonce: other_nonce.public,
    //         public_blinding: other_blinding.public,
    //     };

    //     // Act
    //     let transaction = ResponseData::finalise(&tx_data, &response_data);

    //     // Assert
    //     assert_eq!(transaction.inputs, tx_data.inputs);
    //     assert_eq!(transaction.outputs.len(), 2);
    //     assert_eq!(transaction.outputs[0], tx_data.change_output);
    //     assert_eq!(transaction.outputs[1], response_data.output_commitment);
    //     assert_eq!(
    //         transaction.kernel.excess,
    //         tx_data.blinding_keypair.public + other_blinding.public
    //     );
    //     assert!(transaction.verify());
    // }

    // #[test]
    // #[should_panic(expected = "Signature verification failed")]
    // fn test_incorrect_response() {
    //     // mock tx data
    //     let tx_data = TxData {
    //         inputs: vec![pedersen::commit(Scalar::from(150u64), Scalar::from(10u64))],
    //         amount: Scalar::from(100u64),
    //         change_output: pedersen::commit(Scalar::from(50u64), Scalar::from(5u64)),
    //         nonce_keypair: Keypair::generate(),
    //         blinding_keypair: Keypair::from_private_key(Scalar::from(5u64)),
    //     };

    //     let other_nonce = Keypair::generate();
    //     let other_blinding = Keypair::from_private_key(Scalar::from(6u64));
    //     let output_commitment = pedersen::commit(Scalar::from(100u64), other_blinding.private);

    //     let challenge = Signature::calculate_challenge(
    //         &(tx_data.nonce_keypair.public + other_nonce.public),
    //         &(tx_data.blinding_keypair.public + other_blinding.public),
    //     );

    //     // mock response data
    //     let response_data = ResponseData {
    //         partial_sig: Signature::new(&other_nonce, &other_nonce.private, challenge),
    //         output_commitment,
    //         public_nonce: other_nonce.public,
    //         public_blinding: other_blinding.public,
    //     };

    //     // Act
    //     ResponseData::finalise(&tx_data, &response_data);
    // }

    // #[test]
    // fn test_correct_transaction() {
    //     let ten = Scalar::from(10u64);
    //     let keypair = &Keypair::from_private_key(ten);
    //     let challenge =
    //         Signature::calculate_challenge(&keypair.public, &PublicKey::from_private_key(ten));
    //     let signature = Signature::new(keypair, &ten, challenge);

    //     let transaction = Transaction {
    //         inputs: vec![pedersen::commit(Scalar::from(150u64), ten)],
    //         outputs: vec![
    //             pedersen::commit(Scalar::from(50u64), ten),
    //             pedersen::commit(Scalar::from(100u64), ten),
    //         ],
    //         kernel: Kernel {
    //             excess: PublicKey::from_private_key(ten),
    //             signature,
    //         },
    //     };

    //     assert!(transaction.verify());
    // }

    // #[test]
    // // wrong amount
    // fn test_incorrect_transaction_1() {
    //     let ten = Scalar::from(10u64);
    //     let keypair = &Keypair::from_private_key(ten);
    //     let challenge =
    //         Signature::calculate_challenge(&keypair.public, &PublicKey::from_private_key(ten));
    //     let signature = Signature::new(keypair, &ten, challenge);

    //     let transaction = Transaction {
    //         inputs: vec![pedersen::commit(Scalar::from(150u64), ten)],
    //         outputs: vec![pedersen::commit(Scalar::from(1000u64), ten)],
    //         kernel: Kernel {
    //             excess: PublicKey::from_private_key(ten),
    //             signature,
    //         },
    //     };

    //     assert!(!transaction.verify());
    // }

    // #[test]
    // // wrong signature
    // fn test_incorrect_transaction_2() {
    //     let ten = Scalar::from(10u64);
    //     let keypair = &Keypair::from_private_key(ten);
    //     let challenge = Signature::calculate_challenge(
    //         &keypair.public,
    //         &PublicKey::from_private_key(Scalar::one()),
    //     );
    //     let signature = Signature::new(keypair, &ten, challenge);

    //     let transaction = Transaction {
    //         inputs: vec![pedersen::commit(Scalar::from(150u64), ten)],
    //         outputs: vec![pedersen::commit(Scalar::from(1000u64), ten)],
    //         kernel: Kernel {
    //             excess: PublicKey::from_private_key(ten),
    //             signature,
    //         },
    //     };

    //     assert!(!transaction.verify());
    // }

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

    fn mock_stxo_set(l: &Vec<usize>, C_stxo: &Vec<Commitment>) -> Vec<Commitment> {
        let set = (1..GENS.max_set_size() - C_stxo.len() + 1)
            .map(|_| RistrettoPoint::random(&mut OsRng))
            .collect::<Vec<RistrettoPoint>>();

        l.iter().zip(C_stxo.iter()).fold(set, |mut acc, (l, C_in)| {
            acc.insert(*l, *C_in);
            acc
        })
    }

    fn common_transaction_setup() -> (
        Scalar,
        Scalar,
        Vec<Scalar>,
        Vec<Scalar>,
        Vec<Scalar>,
        Vec<usize>,
        Vec<Commitment>,
    ) {
        let amount = Scalar::from(100u64);
        let change = Scalar::from(50u64);
        let input_values = vec![Scalar::from(120u64), Scalar::from(30u64)];
        let input_blinding_r = vec![Scalar::from(10u64), Scalar::from(15u64)];
        let input_blinding_s = vec![Scalar::from(1u64), Scalar::from(2u64)];
        let pos = vec![0, 1];

        let stxo_outputs = vec![
            pedersen::generalised_commit(input_values[0], input_blinding_r[0], input_blinding_s[0]),
            pedersen::generalised_commit(input_values[1], input_blinding_r[1], input_blinding_s[1]),
        ];
        let stxo_set = mock_stxo_set(&pos, &stxo_outputs);
        (
            amount,
            change,
            input_values,
            input_blinding_r,
            input_blinding_s,
            pos,
            stxo_set,
        )
    }

    fn mock_tx(tx_data: TxData) -> Transaction {
        Transaction {
            inputs: tx_data.inputs,
            schnorr_proofs: tx_data.schnorr_proofs,
            ooom_proofs: tx_data.ooom_proofs,
            outputs: vec![tx_data.change_output],
            kernel: Kernel {
                excess: tx_data.excess_commitment,
                signature: GeneralisedSignature::new_excess_proof(
                    &Keypair::from_private_key(Scalar::zero()),
                    &KeypairH::from_private_key(Scalar::zero()),
                    &Scalar::zero(),
                    &Scalar::zero(),
                    Scalar::zero(),
                ),
            },
        }
    }
}
