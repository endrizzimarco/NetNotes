use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use netnotes::netnotes::{ResponseData, SendData, Transaction};
use netnotes::pedersen::{Commitment, GeneralisedCommitment, GENS};
use rand::rngs::OsRng;

#[derive(Copy, Clone)]
enum SetSize {
    Small,
    Medium,
    Large,
}

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
fn inputs() -> Vec<InputData> {
    let small = setup(SetSize::Small, 2);
    let medium = setup(SetSize::Medium, 2);
    let large = setup(SetSize::Large, 2);

    vec![small, medium, large]
}

fn inputs_different_input_sizes() -> Vec<InputData> {
    let small = setup(SetSize::Small, 100000);
    let medium = setup(SetSize::Small, 200000);
    let large = setup(SetSize::Small, 300000000);

    vec![small, medium, large]
}

fn setup(size: SetSize, inputs_n: u32) -> InputData {
    let size = match size {
        SetSize::Small => 5 as usize,
        SetSize::Medium => 8 as usize,
        SetSize::Large => 10 as usize,
    };
    let set_size = 2u32.pow(size as u32) as usize;

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
        .map(|_| rand::random::<usize>() % size as usize)
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

pub fn netnotes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("netnotes");

    for i in inputs().iter() {
        group.bench_with_input(
            BenchmarkId::new("Generation", i.stxo_set.len()),
            i,
            |b, i| b.iter(|| gen_netnotes_transaction(black_box(i.clone()))),
        );
        let transaction = gen_netnotes_transaction(i.clone());
        group.bench_with_input(
            BenchmarkId::new("Verification", i.stxo_set.len()),
            i,
            |b, _i| b.iter(|| transaction.verify(i.stxo_set.clone())),
        );
    }
    group.finish()
}

criterion_group! {
  name = netnotes_benches;
  config = Criterion::default().sample_size(10);
  targets = netnotes_benchmark
}
criterion_main!(netnotes_benches);
