use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use netnotes::mimblewimble::{ResponseData, SendData, Transaction};
use netnotes::pedersen;
use rand::rngs::OsRng;

fn simu_mw_transaction(blinding_factors: Vec<Scalar>) -> Transaction {
    // create a vector of random values same size of blinding_factors vector
    let values = blinding_factors
        .iter()
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>();

    // create inputs with values and blinding factors
    let inputs = values
        .iter()
        .zip(blinding_factors.iter())
        .map(|(value, blinding_factor)| pedersen::commit(*value, *blinding_factor))
        .collect::<Vec<pedersen::Commitment>>();

    // pick change as 1
    let change = Scalar::one();

    // sum values to an integer and subtract change
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x) - change;

    // Simulate transaction
    let tx_data = Transaction::init(amount, change, blinding_factors, inputs.clone());
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    // return
    transaction
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let blinding_factors = (0..20)
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>();
    c.bench_function("mw_10", |b| {
        b.iter(|| simu_mw_transaction(black_box(blinding_factors.clone())))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
