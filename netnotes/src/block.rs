use std::fmt::{self, Debug, Formatter};
use std::time::SystemTime;

type BlockHash = Vec<u8>;

pub struct Block {
    pub height: u32,
    pub timestamp: u128,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub nonce: u64,
    pub payload: String,
    pub difficulty: u128,
}

impl Debug for Block {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Block[{}]: {} at: {} with: {}, nonce: {}",
            self.height,
            hex::encode(&self.hash),
            self.timestamp,
            self.payload,
            self.nonce
        )
    }
}

impl Block {
    pub fn new(
        height: u32,
        hash: BlockHash,
        prev_hash: BlockHash,
        nonce: u64,
        payload: String,
        difficulty: u128,
    ) -> Self {
        Block {
            height,
            timestamp: now(),
            hash,
            prev_hash,
            nonce,
            payload,
            difficulty,
        }
    }

    pub fn to_hash(&self) -> BlockHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.height.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.payload.as_bytes());
        hasher.update(&self.difficulty.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn mine(&mut self) {
        let mut nonce = 0;
        loop {
            self.nonce = nonce;
            let hash = self.to_hash();
            if check_difficulty(&hash, self.difficulty) {
                self.hash = hash;
                break;
            }
            nonce += 1;
        }
    }
}

pub fn check_difficulty(hash: &BlockHash, difficulty: u128) -> bool {
    difficulty > difficulty_bytes_to_u128(&hash)
}

fn difficulty_bytes_to_u128(difficulty: &[u8]) -> u128 {
    let mut result = 0u128;
    for byte in difficulty {
        result = result << 8;
        result = result | *byte as u128;
    }
    result
}

fn now() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
