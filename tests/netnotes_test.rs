use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use netnotes::netnotes::{ResponseData, SendData, Transaction};
use netnotes::pedersen::{Commitment, GeneralisedCommitment, GENS};
use rand::rngs::OsRng;

fn stxo_set(l: &Vec<usize>, c_stxo: &Vec<GeneralisedCommitment>) -> Vec<GeneralisedCommitment> {
    let set = (0..GENS.0.max_set_size() - c_stxo.len())
        .map(|_| RistrettoPoint::random(&mut OsRng) + GENS.commit_J(Scalar::random(&mut OsRng)))
        .collect::<Vec<GeneralisedCommitment>>();

    l.iter().zip(c_stxo.iter()).fold(set, |mut acc, (l, c)| {
        acc.insert(*l, *c);
        acc
    })
}

fn setup() -> (
    Scalar,
    Scalar,
    Vec<Commitment>,
    Vec<Scalar>,
    Vec<Scalar>,
    Vec<Scalar>,
    Vec<usize>,
    Vec<GeneralisedCommitment>,
) {
    let amount = Scalar::from(100u64);
    let change = Scalar::from(50u64);
    let input_values = vec![Scalar::from(120u64), Scalar::from(30u64)];
    let input_blinding_r = vec![Scalar::from(10u64), Scalar::from(15u64)];
    let input_blinding_s = vec![Scalar::from(1u64), Scalar::from(2u64)];
    let pos = vec![0, 1];
    let inputs = vec![
        GENS.commit_hj(input_blinding_r[0], input_values[0]),
        GENS.commit_hj(input_blinding_r[1], input_values[1]),
    ];

    let stxo_outputs = vec![
        GENS.generalised_commit(input_values[0], input_blinding_r[0], input_blinding_s[0]),
        GENS.generalised_commit(input_values[1], input_blinding_r[1], input_blinding_s[1]),
    ];
    let stxo_set = stxo_set(&pos, &stxo_outputs);
    (
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set,
    )
}

#[test]
// Tests all modules working together to form a NetNotes transaction
fn test_valid_transaction() {
    let (amount, change, inputs, input_values, input_blinding_r, input_blinding_s, pos, stxo_set) =
        setup();

    // Simulate transaction
    let tx_data = Transaction::init(
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set.clone(),
    );
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify(stxo_set));
}

#[test]
#[should_panic]
fn test_transaction_no_change() {
    let (amount, _change, inputs, input_values, input_blinding_r, input_blinding_s, pos, stxo_set) =
        setup();

    // override change
    let change = Scalar::zero();

    let tx_data = Transaction::init(
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set.clone(),
    );
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify(stxo_set));
}

#[test]
#[should_panic]
fn test_transaction_over_amount() {
    let (amount, change, inputs, input_values, input_blinding_r, input_blinding_s, pos, stxo_set) =
        setup();

    // override amount
    let amount = Scalar::from(10000u64);

    // Simulate transaction
    let tx_data = Transaction::init(
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set.clone(),
    );
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify(stxo_set));
}

#[test]
#[should_panic]
fn test_transaction_modified_input() {
    let (
        amount,
        change,
        inputs,
        mut input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set,
    ) = setup();

    // get length of inputs
    let len = input_values.len();

    // change last input element
    input_values[len - 1] = Scalar::zero();

    // Simulate transaction
    let tx_data = Transaction::init(
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set.clone(),
    );
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify(stxo_set));
}

#[test]
#[should_panic]
fn test_transaction_wrong_blinding_factor() {
    let (
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        mut stxo_set,
    ) = setup();

    // change last blinding factor element
    stxo_set[1] = RistrettoPoint::random(&mut rand::thread_rng());

    // Simulate transaction
    let tx_data = Transaction::init(
        amount,
        change,
        inputs,
        input_values,
        input_blinding_r,
        input_blinding_s,
        pos,
        stxo_set.clone(),
    );
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify(stxo_set));
}
