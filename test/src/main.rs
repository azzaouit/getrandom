use ed25519_dalek::SigningKey;
use ed25519_dalek::SECRET_KEY_LENGTH;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use std::io::Read;

struct PCG {
    multiplier: u64,
    increment: u64,
    state: u64,
}

impl PCG {
    fn new_pcg() -> Self {
        Self {
            multiplier: 6364136223846793005,
            increment: 1442695040888963407,
            state: 0x4d595df4d0f33173,
        }
    }
}

impl CryptoRng for PCG {}

impl RngCore for PCG {
    fn next_u32(&mut self) -> u32 {
        let mut x: u64 = self.state;
        let count = (x >> 59) as u32;
        self.state = x.wrapping_mul(self.multiplier).wrapping_add(self.increment);
        x ^= x >> 18;
        let y = ((x >> 27) as u32).rotate_right(count as u32);
        y
    }
    fn next_u64(&mut self) -> u64 {
        self.next_u32() as u64 | (self.next_u32() as u64) << 31
    }
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let nw = buf.len() >> 2;
        let rem = buf.len() & 0x3;
        let mut ii = 0;
        for _ in 0..nw {
            let r = self.next_u32();
            for j in 0..4 {
                buf[ii] = (r >> 8 * j) as u8;
                ii += 1;
            }
        }
        if rem != 0 {
            let r = self.next_u32();
            for i in 0..rem {
                buf[ii] = (r >> 8 * i) as u8;
                ii += 1;
            }
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl Read for PCG {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fill_bytes(buf);
        Ok(buf.len())
    }
}

fn main() {
    let mut csprng = OsRng;
    let mut mycsprng = PCG::new_pcg();
    let public_key = SigningKey::generate(&mut csprng).verifying_key();
    const N: usize = 100000;
    const K: usize = SECRET_KEY_LENGTH * N;
    let mut rand_bytes = [0u8; K];
    mycsprng.fill_bytes(&mut rand_bytes);
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];

    for i in 0..K - SECRET_KEY_LENGTH {
        for j in 0..SECRET_KEY_LENGTH {
            secret_key_bytes[j] = rand_bytes[i + j];
        }
        let key = SigningKey::from_bytes(&secret_key_bytes);
        if key.verifying_key() == public_key {
            println!("Found private key!");
            dbg!(&key);
            break;
        }
    }
}
