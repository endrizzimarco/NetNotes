mod block;
use block::Block;

fn main() {
    let mut block = Block::new(
        0,
        0,
        vec![0; 32],
        vec![0; 32],
        0,
        "Genesis Block".to_string(),
    );
    block.block_hash = block.hash();
    println!("{:?}", block);
}
