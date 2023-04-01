use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use netnotes::mimblewimble::{ResponseData, SendData, Transaction};
use netnotes::pedersen::{Commitment, GENS};
use rand::rngs::OsRng;

#[derive(Clone)]
struct InputData {
    amount: Scalar,
    change: Scalar,
    blinding_factors: Vec<Scalar>,
    inputs: Vec<Commitment>,
}

fn inputs() -> Vec<InputData> {
    let bf_small = gen_blinding_factors(2u32);
    let bf_medium = gen_blinding_factors(2u32.pow(5));
    let bf_large = gen_blinding_factors(2u32.pow(8));

    vec![setup(bf_small), setup(bf_medium), setup(bf_large)]
}

fn setup(blinding_factors: Vec<Scalar>) -> InputData {
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

    // pick change as 1
    let change = Scalar::one();

    // sum values to an integer and subtract change
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x) - change;

    InputData {
        amount,
        change,
        blinding_factors,
        inputs,
    }
}

fn gen_mw_transaction(input: InputData) -> Transaction {
    // Simulate transaction
    let tx_data = Transaction::init(
        input.amount,
        input.change,
        input.blinding_factors,
        input.inputs,
    ); // 260 us
    let send_data = tx_data.send(); // 261 us
    let response_data = SendData::respond(&send_data); // 470 us
    let transaction = ResponseData::finalise(&tx_data, &response_data); // 625 us

    transaction
}

fn gen_blinding_factors(n: u32) -> Vec<Scalar> {
    (0..n)
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>()
}

pub fn mimblewimble_tx_gen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("mimblewimble_gen");

    for i in inputs().iter() {
        group.bench_with_input(format!("mw_gen:{}", i.blinding_factors.len()), i, |b, i| {
            b.iter(|| gen_mw_transaction(black_box(i.clone())))
        });
    }
}

pub fn mimblewimble_tx_verify_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("mimblewimble_verify");

    for i in inputs().iter() {
        let transaction = gen_mw_transaction(i.clone());
        group.bench_with_input(
            format!("mw_verify:{}", i.blinding_factors.len()),
            i,
            |b, i| b.iter(|| transaction.verify()),
        );
    }
}

criterion_group!(gen_benches, mimblewimble_tx_gen_benchmark);
criterion_group!(verify_benches, mimblewimble_tx_verify_benchmark);
criterion_main!(gen_benches, verify_benches);
