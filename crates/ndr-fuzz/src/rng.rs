//! A tiny deterministic PRNG (SplitMix64) so fuzz runs are reproducible from a
//! seed without pulling in an external crate.

pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform in `[0, n)` (n > 0).
    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as u32
    }

    /// True with probability `p_num / p_den`.
    pub fn chance(&mut self, p_num: u32, p_den: u32) -> bool {
        self.below(p_den) < p_num
    }

    /// Pick one element index from `len`.
    pub fn pick(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            self.below(len as u32) as usize
        }
    }
}
