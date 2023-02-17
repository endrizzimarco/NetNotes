use std::fmt::{self, Debug, Formatter};

type BlockHash = Vec<u8>;

pub struct Block {
    pub height: u32,
    pub timestamp: u128,
    pub block_hash: BlockHash,
    pub prev_block_hash: BlockHash,
    pub nonce: u64,
    pub payload: String,
}

impl Debug for Block {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Block[{}]: {} at: {} with: {}",
            self.height,
            hex::encode(&self.block_hash),
            self.timestamp,
            self.payload
        )
    }
}

impl Block {
    pub fn new(
        height: u32,
        timestamp: u128,
        block_hash: BlockHash,
        prev_block_hash: BlockHash,
        nonce: u64,
        payload: String,
    ) -> Self {
        Block {
            height,
            timestamp,
            block_hash,
            prev_block_hash,
            nonce,
            payload,
        }
    }

    pub fn hash(&self) -> BlockHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.height.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.prev_block_hash);
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.payload.as_bytes());
        hasher.finalize().as_bytes().to_vec()
    }
}
