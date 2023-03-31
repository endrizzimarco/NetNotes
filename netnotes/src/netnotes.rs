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
            output_blindings: (s_output, blinding_diff),
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
        let verify_kernel_excess = signature.verify_excess_proof(excess, challenge);
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
    pub fn finalise(tx: &TxData, resp: &ResponseData) -> Transaction {
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
            inputs: tx.inputs.clone(),
            schnorr_proofs: tx.schnorr_proofs.clone(),
            ooom_proofs: tx.ooom_proofs.clone(),
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

    #[test]
    fn test_invalid_ooom_proofs() {
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

        let mut transaction = mock_tx(tx_data);
        // Add a second blinding factor to the first input
        transaction.inputs[0] = pedersen::commit_hj(Scalar::from(120u64), Scalar::from(11u64));
        assert!(!transaction.verify_ooom_proofs(stxo_set));
    }

    #[test]
    fn test_send_transaction() {
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

        let send_data = tx_data.send();

        // Assert
        assert_eq!(send_data.amount, amount);
        assert_eq!(send_data.excess_commitment, tx_data.excess_commitment);
        assert_eq!(send_data.nonces_commitment, tx_data.nonces_commitment);
    }

    #[test]
    fn test_finalise_transaction() {
        // mock tx data
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
        let send_data = tx_data.send();

        // mock response data
        let other_blinding = Keypair::generate();
        let other_blinding_h = KeypairH::generate();
        let other_nonce = Keypair::generate();
        let other_nonce_h = KeypairH::generate();
        let excess_commitment = (other_blinding.public + other_blinding_h.public).0;
        let nonces_commitment = (other_nonce.public + other_nonce_h.public).0;

        let challenge = GeneralisedSignature::calculate_challenge(
            &(send_data.excess_commitment + excess_commitment),
            &(send_data.nonces_commitment + nonces_commitment),
        );

        let partial_sig = GeneralisedSignature::new_excess_proof(
            &other_nonce,
            &other_nonce_h,
            &other_blinding.private,
            &other_blinding_h.private,
            challenge,
        );
        let output_commitment = pedersen::generalised_commit(
            send_data.amount,
            other_blinding_h.private,
            other_blinding.private,
        );

        let mock_response = ResponseData {
            partial_sig,
            output_commitment,
            public_nonces: (other_nonce.public, other_nonce_h.public),
            public_blinding: (other_blinding.public, other_blinding_h.public),
        };

        // Act
        let transaction = ResponseData::finalise(&tx_data, &mock_response);

        // Assert
        assert_eq!(transaction.inputs, tx_data.inputs);
        assert_eq!(transaction.outputs.len(), 2);
        assert_eq!(transaction.outputs[0], tx_data.change_output);
        assert_eq!(transaction.outputs[1], mock_response.output_commitment);
        assert_eq!(
            transaction.kernel.excess,
            tx_data.excess_commitment + excess_commitment
        );
        assert!(transaction.verify(stxo_set));
    }

    #[test]
    #[should_panic(expected = "Signature verification failed")]
    fn test_incorrect_response() {
        // mock tx data
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

        // mock response data
        let other_blinding = Keypair::generate();
        let other_blinding_h = KeypairH::generate();
        let other_nonce = Keypair::generate();
        let other_nonce_h = KeypairH::generate();
        let excess_commitment = (other_blinding.public + other_blinding_h.public).0;
        let nonces_commitment = (other_nonce.public + other_nonce_h.public).0;

        let challenge = GeneralisedSignature::calculate_challenge(
            &(tx_data.excess_commitment + excess_commitment),
            &(tx_data.nonces_commitment + nonces_commitment),
        );

        let partial_sig = GeneralisedSignature::new_excess_proof(
            &other_nonce,
            &other_nonce_h,
            &other_nonce.private,
            &other_blinding_h.private,
            challenge,
        );
        let output_commitment = pedersen::generalised_commit(
            tx_data.amount,
            other_blinding_h.private,
            other_blinding.private,
        );

        let mock_response = ResponseData {
            partial_sig,
            output_commitment,
            public_nonces: (other_nonce.public, other_nonce_h.public),
            public_blinding: (other_blinding.public, other_blinding_h.public),
        };

        // Act
        ResponseData::finalise(&tx_data, &mock_response);
    }

    #[test]
    fn test_correct_transaction() {
        let ten = Scalar::from(10u64);
        let keypair = &Keypair::from_private_key(ten);
        let keypair_H = &KeypairH::from_private_key(ten);
        let challenge = GeneralisedSignature::calculate_challenge(
            &(keypair.public.0 + keypair_H.public.0),
            &(PublicKey::from_private_key(ten).0 + PublicKeyH::from_private_key(ten).0),
        );
        let signature =
            GeneralisedSignature::new_excess_proof(keypair, keypair_H, &ten, &ten, challenge);
        let input = pedersen::commit_hj(ten, Scalar::from(150u64));
        let stxo_set = mock_stxo_set(&vec![0], &vec![input + pedersen::commit_G(ten)]);

        let transaction = Transaction {
            inputs: vec![input],
            schnorr_proofs: Transaction::generate_schnorr_proofs(
                vec![Scalar::from(150u64)],
                vec![ten],
            ),
            ooom_proofs: Transaction::generate_ooom_proofs(
                stxo_set.clone(),
                vec![0],
                &vec![input],
                vec![ten],
            ),
            outputs: vec![
                pedersen::generalised_commit(Scalar::from(50u64), ten, ten),
                pedersen::generalised_commit(Scalar::from(100u64), ten, Scalar::zero()),
            ],
            kernel: Kernel {
                excess: PublicKey::from_private_key(ten).0 + PublicKeyH::from_private_key(ten).0,
                signature,
            },
        };

        assert!(transaction.verify(stxo_set));
    }

    #[test]
    // wrong amount
    fn test_incorrect_transaction_1() {
        let ten = Scalar::from(10u64);
        let keypair = &Keypair::from_private_key(ten);
        let keypair_H = &KeypairH::from_private_key(ten);
        let challenge = GeneralisedSignature::calculate_challenge(
            &(keypair.public.0 + keypair_H.public.0),
            &(PublicKey::from_private_key(ten).0 + PublicKeyH::from_private_key(ten).0),
        );
        let signature =
            GeneralisedSignature::new_excess_proof(keypair, keypair_H, &ten, &ten, challenge);
        let input = pedersen::commit_hj(ten, Scalar::from(149u64));
        let stxo_set = mock_stxo_set(&vec![0], &vec![input + pedersen::commit_G(ten)]);

        let transaction = Transaction {
            inputs: vec![input],
            schnorr_proofs: Transaction::generate_schnorr_proofs(
                vec![Scalar::from(150u64)],
                vec![ten],
            ),
            ooom_proofs: Transaction::generate_ooom_proofs(
                stxo_set.clone(),
                vec![0],
                &vec![input],
                vec![ten],
            ),
            outputs: vec![
                pedersen::generalised_commit(Scalar::from(50u64), ten, ten),
                pedersen::generalised_commit(Scalar::from(100u64), ten, Scalar::zero()),
            ],
            kernel: Kernel {
                excess: PublicKey::from_private_key(ten).0 + PublicKeyH::from_private_key(ten).0,
                signature,
            },
        };

        assert!(!transaction.verify(stxo_set));
    }

    #[test]
    // wrong signature
    fn test_incorrect_transaction_2() {
        let ten = Scalar::from(10u64);
        let keypair = &Keypair::from_private_key(ten);
        let keypair_H = &KeypairH::from_private_key(ten);
        let challenge = GeneralisedSignature::calculate_challenge(
            &(keypair.public.0 + keypair_H.public.0),
            &(PublicKey::from_private_key(ten).0 + PublicKeyH::from_private_key(ten).0),
        );
        let signature = GeneralisedSignature::new_excess_proof(
            keypair,
            keypair_H,
            &Scalar::zero(),
            &ten,
            challenge,
        );
        let input = pedersen::commit_hj(ten, Scalar::from(149u64));
        let stxo_set = mock_stxo_set(&vec![0], &vec![input + pedersen::commit_G(ten)]);

        let transaction = Transaction {
            inputs: vec![input],
            schnorr_proofs: Transaction::generate_schnorr_proofs(
                vec![Scalar::from(150u64)],
                vec![ten],
            ),
            ooom_proofs: Transaction::generate_ooom_proofs(
                stxo_set.clone(),
                vec![0],
                &vec![input],
                vec![ten],
            ),
            outputs: vec![
                pedersen::generalised_commit(Scalar::from(50u64), ten, ten),
                pedersen::generalised_commit(Scalar::from(100u64), ten, Scalar::zero()),
            ],
            kernel: Kernel {
                excess: PublicKey::from_private_key(ten).0 + PublicKeyH::from_private_key(ten).0,
                signature,
            },
        };

        assert!(!transaction.verify(stxo_set));
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

    #[allow(dead_code)]
    fn mock_stxo_set(
        l: &Vec<usize>,
        C_stxo: &Vec<GeneralisedCommitment>,
    ) -> Vec<GeneralisedCommitment> {
        let set = (1..GENS.max_set_size() - C_stxo.len() + 1)
            .map(|_| {
                RistrettoPoint::random(&mut OsRng) + pedersen::commit_J(Scalar::random(&mut OsRng))
            })
            .collect::<Vec<GeneralisedCommitment>>();

        l.iter().zip(C_stxo.iter()).fold(set, |mut acc, (l, C_in)| {
            acc.insert(*l, *C_in);
            acc
        })
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
