use super::block::{check_difficulty, Block};
use std::fmt::{self, Debug, Formatter};

pub struct Blockchain {
    pub blocks: Vec<Block>,
}

impl Debug for Blockchain {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Blockchain[{}]:", self.blocks.len())?;
        for block in &self.blocks {
            write!(f, "\n\t{:?}", block)?;
        }
        Ok(())
    }
}

impl Blockchain {
    pub fn verify(&self) -> bool {
        for (i, block) in self.blocks.iter().enumerate() {
            if i == 0 {
                continue; // skip genesis block
            }
            if block.height != i as u32 {
                println!("Index mismatch {} != {}", block.height, i);
                return false;
            }
            if !check_difficulty(&block.hash, block.difficulty) {
                println!("Difficulty check failed");
                return false;
            }
            let prev_block = &self.blocks[i - 1];
            if block.prev_hash != prev_block.hash {
                println!(
                    "Linking hash mismatch {} != {}",
                    hex::encode(&block.prev_hash),
                    hex::encode(&self.blocks[i - 1].hash)
                );
                return false;
            }
            if prev_block.timestamp >= block.timestamp {
                println!(
                    "Timestamp check failed {} >= {}",
                    prev_block.timestamp, block.timestamp
                );
                return false;
            }
        }
        true
    }
}
