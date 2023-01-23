use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsBasepointTable;
use curve25519_dalek::scalar::Scalar;
use rand;

fn main() {
    #![allow(non_snake_case)]
    let scalar1: u32 = rand::random();
    let scalar2: u32 = rand::random();
    // multiply the basepoint by the scalar
    let G = &constants::ED25519_BASEPOINT_POINT * &Scalar::from(scalar1);
    let G_bt = EdwardsBasepointTable::create(&G);
    let H = G * &Scalar::from(scalar2);
    let H_bt = EdwardsBasepointTable::create(&H);

    // println!("Random point on the curve: {:?}", H);

    //blinding factor + amount curve point TxIN1 (a=10, r=14): 14*G, 10*H
    let r1 = Scalar::from(14u64);
    let v1 = Scalar::from(10u64);
    let rG_1 = EdwardsBasepointTable::basepoint_mul(&G_bt, &r1);
    let vH_1 = EdwardsBasepointTable::basepoint_mul(&H_bt, &v1);

    //TxIN2 from the article example (a=30, r=85): 85*G, 30*H
    let r2 = Scalar::from(85u64);
    let v2 = Scalar::from(30u64);
    let rG_2 = EdwardsBasepointTable::basepoint_mul(&G_bt, &r2);
    let vH_2 = EdwardsBasepointTable::basepoint_mul(&H_bt, &v2);

    // //TxIN3 from the article example (a=10, r=43): 43*G, 10*H
    let r3 = Scalar::from(43u64);
    let v3 = Scalar::from(10u64);
    let rG_3 = EdwardsBasepointTable::basepoint_mul(&G_bt, &r3);
    let vH_3 = EdwardsBasepointTable::basepoint_mul(&H_bt, &v3);

    //calculate pedersen EC commitments for the TxIN's
    //TxIN1: c=14*G+10*H
    let c1 = rG_1 + vH_1;
    //TxIN2: c=85*G+30*H
    let c2 = rG_2 + vH_2;
    //TxIN3: c=43*G+10*H
    let c3 = rG_3 + vH_3;

    let combined = rG_1 + vH_1 + rG_2 + vH_2 + rG_3 + vH_3;
    println!(
        "Do properties hold: {:?}",
        (c1 + c2 + c3).compress() == combined.compress()
    );

    //blinding factor and curve point for TxOUT1 from the article example (a=40, r=28): 28*G, 40*H
    let r4 = Scalar::from(28u64);
    let v4 = Scalar::from(40u64);
    let rG_4 = EdwardsBasepointTable::basepoint_mul(&G_bt, &r4);
    let vH_4 = EdwardsBasepointTable::basepoint_mul(&H_bt, &v4);

    //TxOUT2 from the article example (a=8, r=33): 33*G, 8*H
    let r5 = Scalar::from(33u64);
    let v5 = Scalar::from(8u64);
    let rG_5 = EdwardsBasepointTable::basepoint_mul(&G_bt, &r5);
    let vH_5 = EdwardsBasepointTable::basepoint_mul(&H_bt, &v5);

    // //TxOUT3, a.k.a the TxOUT for the fee, (a=2, r=83): 83*G, 2*H
    // //the 83 is calculated in the following as the diff between input and output G
    // let r6 = Scalar::from(83u64);
    // let v6 = Scalar::from(2u64);
    // let rG_6 = EdwardsBasepointTable::basepoint_mul(&G_bt, &r6);
    // let vH_6 = EdwardsBasepointTable::basepoint_mul(&H_bt, &v6);

    //calculate pedersen EC commitments for the TxOUT's
    //TxOUT1: c=28*G+40*H
    let c4 = rG_4 + vH_4;
    //TxOUT2: c=33*G+8*H
    let c5 = rG_5 + vH_5;
    //TxOUT3: c=83*G+2*H
    // let c6 = rG_6 + vH_6;

    //TxOUT3, a.k.a the TxOUT for the fee, (a=2, r=83): 83*G, 2*H
    //the 83 is calculated in the following as the diff between input and output G
    let r_i_total = r1 + r2 + r3;
    let r_o_total = r4 + r5;
    let r_fee = r_i_total - r_o_total; // 84*G
    let v_fee = Scalar::from(2u64); // 2*H
    let rG_fee = EdwardsBasepointTable::basepoint_mul(&G_bt, &r_fee);
    let vH_fee = EdwardsBasepointTable::basepoint_mul(&H_bt, &v_fee);
    let c_fee = rG_fee + vH_fee;

    //combined commitment for all TxOUT's together
    let c_all_o = c4 + c5 + c_fee;

    //calculate directly the commitment to zero, z=0*G + 0*H
    //so can compare to diff of above generated combined TxIN and TxOUT commitments
    let r_z = Scalar::from(0u64);
    let v_z = Scalar::from(0u64);
    let zG = EdwardsBasepointTable::basepoint_mul(&G_bt, &r_z);
    let zH = EdwardsBasepointTable::basepoint_mul(&H_bt, &v_z);
    let c_z = zG + zH;
    println!("Commitment to zero: {:?}", c_z);
    let c_compare = c1 + c2 + c3 - c4 - c5 - c_fee;
    println!("Diff between TxIN and TxOUT commitments: {:?}", c_compare);
}
