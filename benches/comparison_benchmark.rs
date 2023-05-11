use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use netnotes::mimblewimble::{
    ResponseData as MWResponse, SendData as MWSend, Transaction as MWTransaction,
};
use netnotes::netnotes::{ResponseData, SendData, Transaction};
use netnotes::pedersen::{Commitment, GeneralisedCommitment, GENS};
use rand::rngs::OsRng;

#[derive(Clone)]
struct InputData {
    amount: Scalar,
    change: Scalar,
    inputs: Vec<Commitment>,
    values: Vec<Scalar>,
    r_blinding: Vec<Scalar>,
    s_blinding: Vec<Scalar>,
    positions: Vec<usize>,
    stxo_set: Vec<GeneralisedCommitment>,
}

#[derive(Clone)]
struct MWInputData {
    amount: Scalar,
    change: Scalar,
    blinding_factors: Vec<Scalar>,
    inputs: Vec<Commitment>,
}

fn inputs() -> Vec<InputData> {
    let small = setup((2, 13), 1);
    let medium = setup((8, 5), 1);
    let large = setup((4, 8), 1);

    vec![small, medium, large]
}

fn mw_setup(blinding_factors: Vec<Scalar>) -> MWInputData {
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

    MWInputData {
        amount,
        change,
        blinding_factors,
        inputs,
    }
}

fn gen_blinding_factors(n: u32) -> Vec<Scalar> {
    (0..n)
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>()
}

fn gen_mw_transaction(input: MWInputData) -> MWTransaction {
    // Simulate transaction
    let tx_data = MWTransaction::init(
        input.amount,
        input.change,
        input.blinding_factors,
        input.inputs,
    );
    let send_data = tx_data.send();
    let response_data = MWSend::respond(&send_data);
    let transaction = MWResponse::finalise(&tx_data, &response_data);

    transaction
}

fn setup(size: (usize, usize), inputs_n: u32) -> InputData {
    let set_size = size.0.pow(size.1 as u32) as usize;

    let mut rng = OsRng;
    let r_blinding = (0..inputs_n)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();

    let s_blinding = (0..inputs_n)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();

    let values = (0..inputs_n)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();

    let change = Scalar::one();
    let amount = values.iter().fold(Scalar::zero(), |acc, x| acc + x) - change;

    // get inputs by zipping values and blinding factors
    let inputs = values
        .iter()
        .zip(r_blinding.iter())
        .map(|(v, r)| GENS.commit_hj(*r, *v))
        .collect::<Vec<Commitment>>();

    // Add s_blinding to commitment to get generalised commitment
    let stxo_inputs = inputs
        .iter()
        .zip(s_blinding.iter())
        .map(|(c, s)| *c + GENS.commit_G(*s))
        .collect::<Vec<GeneralisedCommitment>>();

    // create a vector<usize> of length inputs_n with random values between 0 and size
    let positions = (0..inputs_n)
        .map(|_| rand::random::<usize>() % size.0 as usize)
        .collect::<Vec<usize>>();

    let stxo_set = stxo_set(&positions, &stxo_inputs, set_size);

    InputData {
        amount,
        change,
        inputs,
        values,
        r_blinding,
        s_blinding,
        positions,
        stxo_set,
    }
}

fn gen_netnotes_transaction(input: InputData) -> Transaction {
    let tx_data = Transaction::init(
        input.amount,
        input.change,
        input.inputs,
        input.values,
        input.r_blinding,
        input.s_blinding,
        input.positions,
        input.stxo_set.clone(),
    ); // 14ms
    let send_data = tx_data.send();
    let response_data = SendData::respond(&send_data, &input.stxo_set);
    let transaction = ResponseData::finalise(&tx_data, &response_data);

    transaction // 14ms
}

fn stxo_set(
    l: &Vec<usize>,
    c_stxo: &Vec<GeneralisedCommitment>,
    size: usize,
) -> Vec<GeneralisedCommitment> {
    let set = (0..size - c_stxo.len())
        .map(|_| RistrettoPoint::random(&mut OsRng) + GENS.commit_J(Scalar::random(&mut OsRng)))
        .collect::<Vec<GeneralisedCommitment>>();

    l.iter().zip(c_stxo.iter()).fold(set, |mut acc, (l, c)| {
        acc.insert(*l, *c);
        acc
    })
}

pub fn comparison_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison");
    let mw_inputs = inputs()
        .iter()
        .map(|_| mw_setup(gen_blinding_factors(1)))
        .collect::<Vec<_>>();
    let inputs = inputs().clone();
    for (i, mw_i) in inputs.iter().zip(mw_inputs.iter()) {
        group.bench_with_input(
            BenchmarkId::new("NetNotes Generation", i.stxo_set.len()),
            i,
            |b, i| b.iter(|| gen_netnotes_transaction(black_box(i.clone()))),
        );
        group.bench_with_input(
            BenchmarkId::new("Mimblewimble Generation", i.stxo_set.len()),
            mw_i,
            |b, i| b.iter(|| gen_mw_transaction(black_box(i.clone()))),
        );
        let transaction = gen_netnotes_transaction(i.clone());
        let mw_transaction = gen_mw_transaction(mw_i.clone());
        group.bench_with_input(
            BenchmarkId::new("NetNotes Verification", i.stxo_set.len()),
            i,
            |b, _i| b.iter(|| transaction.verify(i.stxo_set.clone())),
        );
        group.bench_with_input(
            BenchmarkId::new("Mimblewimble Verification", i.stxo_set.len()),
            mw_i,
            |b, _i| b.iter(|| mw_transaction.verify()),
        );
    }
    group.finish()
}

criterion_group! {
  name = comparison_benches;
  config = Criterion::default().sample_size(10);
  targets = comparison_benchmark
}
criterion_main!(comparison_benches);
