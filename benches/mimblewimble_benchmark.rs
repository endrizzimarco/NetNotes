use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
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
    let small = gen_blinding_factors(2u32.pow(5));
    let medium = gen_blinding_factors(2u32.pow(10));
    let large = gen_blinding_factors(2u32.pow(14));
    let x_large = gen_blinding_factors(2u32.pow(16));

    vec![setup(small), setup(medium), setup(large), setup(x_large)]
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

pub fn mimblewimble_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("mimblewimble");

    for i in inputs().iter() {
        group.bench_with_input(
            BenchmarkId::new("Generation", i.blinding_factors.len()),
            i,
            |b, i| b.iter(|| gen_mw_transaction(black_box(i.clone()))),
        );
        let transaction = gen_mw_transaction(i.clone());
        group.bench_with_input(
            BenchmarkId::new("Verification", i.blinding_factors.len()),
            i,
            |b, _i| b.iter(|| transaction.verify()),
        );
    }
    group.finish();
}

criterion_group!(gen_benches, mimblewimble_benchmarks);
criterion_main!(gen_benches);
