use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use netnotes::mimblewimble::{ResponseData, SendData, Transaction};
use netnotes::pedersen;
use rand::rngs::OsRng;

fn gen_mw_transaction(blinding_factors: Vec<Scalar>) -> Transaction {
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

fn gen_blinding_factors(n: u32) -> Vec<Scalar> {
    (0..n)
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>()
}

pub fn mimblewimble_tx_gen_benchmark(c: &mut Criterion) {
    let bf_small = gen_blinding_factors(2u32.pow(10));
    let bf_medium = gen_blinding_factors(2u32.pow(14));
    let bf_large = gen_blinding_factors(2u32.pow(16));

    c.bench_function("mw_gen:2^10", |b| {
        b.iter(|| gen_mw_transaction(black_box(bf_small.clone())))
    });
    c.bench_function("mw_gen:2^14", |b| {
        b.iter(|| gen_mw_transaction(black_box(bf_medium.clone())))
    });
    c.bench_function("mw_gen:2^16", |b| {
        b.iter(|| gen_mw_transaction(black_box(bf_large.clone())))
    });
}

pub fn mimblewimble_tx_verify_benchmark(c: &mut Criterion) {
    let bf_small = gen_blinding_factors(2u32.pow(10));
    let bf_medium = gen_blinding_factors(2u32.pow(14));
    let bf_large = gen_blinding_factors(2u32.pow(16));

    let tx_small = gen_mw_transaction(bf_small.clone());
    let tx_medium = gen_mw_transaction(bf_medium.clone());
    let tx_large = gen_mw_transaction(bf_large.clone());

    c.bench_function("mw_verify:2^10", |b| b.iter(|| tx_small.verify()));
    c.bench_function("mw_verify:2^14", |b| b.iter(|| tx_medium.verify()));
    c.bench_function("mw_verify:2^16", |b| b.iter(|| tx_large.verify()));
}

criterion_group!(gen_benches, mimblewimble_tx_gen_benchmark);
criterion_group!(verify_benches, mimblewimble_tx_verify_benchmark);
criterion_main!(gen_benches, verify_benches);
