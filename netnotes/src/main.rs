mod block;
use block::Block;
mod blockchain;
use blockchain::Blockchain;
mod mimblewimble;
mod pedersen;
mod schnorr;

fn main() {
    let mut block = Block::new(
        0,
        vec![0; 32],
        vec![0; 32],
        0,
        "Genesis Block".to_string(),
        0x00fffffffffffffffffffffffffffff,
    );
    block.mine();

    let last_hash = block.hash.clone();

    let mut blockchain = Blockchain {
        blocks: vec![block],
    };

    let mut block2 = Block::new(
        1,
        vec![0; 32],
        last_hash,
        0,
        "Test block".to_string(),
        0x00ffffffffffffffffffffffffffffffff,
    );
    block2.mine();

    blockchain.blocks.push(block2);

    blockchain.verify();

    println!("{:?}", blockchain);
}
