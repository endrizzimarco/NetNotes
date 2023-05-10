use curve25519_dalek::scalar::Scalar;
use netnotes::mimblewimble::{ResponseData, SendData, Transaction};
use netnotes::pedersen::{Commitment, GENS};
use rand::rngs::OsRng;

fn setup() -> (Vec<Scalar>, Vec<Scalar>, Vec<Commitment>) {
    let blinding_factors = (0..2)
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>();

    // create a vector of random values same size of blinding_factors vector
    let values = blinding_factors
        .iter()
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>();

    // create inputs with values and blinding factors
    let inputs = values
        .iter()
        .zip(blinding_factors.iter())
        .map(|(value, blinding_factor)| GENS.commit(*value, *blinding_factor))
        .collect::<Vec<Commitment>>();

    (blinding_factors, values, inputs)
}

#[test]
// Tests all modules working together to form a Mimblewimble transaction
fn test_valid_transaction() {
    let (blinding_factors, values, inputs) = setup();

    // pick change as 1
    let change = Scalar::one();

    // get total amount for receiver
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x) - change;

    // Simulate transaction
    let tx_data = Transaction::init(amount, change, blinding_factors, inputs.clone());
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify());
}

#[test]
#[should_panic]
fn test_transaction_no_change() {
    let (blinding_factors, values, inputs) = setup();

    // pick change as 1
    let change = Scalar::one();

    // sum values to an integer and subtract change
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x);

    // Simulate transaction
    let tx_data = Transaction::init(amount, change, blinding_factors, inputs.clone());
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify());
}

#[test]
#[should_panic]
fn test_transaction_over_amount() {
    let (blinding_factors, values, inputs) = setup();

    // pick change as 1
    let change = Scalar::one();

    // sum values to an integer and subtract change
    let amount = values.iter().fold(Scalar::one(), |acc, x| acc + x) - change;

    // Simulate transaction
    let tx_data = Transaction::init(amount, change, blinding_factors, inputs.clone());
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify());
}

#[test]
#[should_panic]
fn test_transaction_modified_input() {
    let (blinding_factors, values, mut inputs) = setup();
    // get length of inputs
    let len = inputs.len();

    // change last input element
    inputs[len - 1] = GENS.commit(Scalar::one(), Scalar::one());

    // pick change as 1
    let change = Scalar::one();

    // sum values to an integer and subtract change
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x);

    // Simulate transaction
    let tx_data = Transaction::init(amount, change, blinding_factors, inputs.clone());
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify());
}

#[test]
#[should_panic]
fn test_transaction_wrong_blinding_factor() {
    let (mut blinding_factors, values, inputs) = setup();
    // get length of blinding_factors
    let len = blinding_factors.len();

    // change last blinding factor element
    blinding_factors[len - 1] = Scalar::one();

    // pick change as 1
    let change = Scalar::one();

    // sum values to an integer and subtract change
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x);

    // Simulate transaction
    let tx_data = Transaction::init(amount, change, blinding_factors, inputs.clone());
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    assert!(transaction.verify());
}
