//! Radamsa-style content mutation + a dictionary of bug-triggering tokens.
//!
//! This runs at the *content* layer - the bytes inside a `byte[]` buffer or a
//! `char` string - while the surrounding NDR framing and `size_is` lengths stay
//! valid. That's the key difference from a black-box mutator like radamsa: our
//! output still unmarshals, so it reaches the handler (where the bugs are)
//! instead of bouncing at the NDR layer with `0x6f7`. It composes with the
//! coverage-guided loop: mutations that light new blocks get bred further.

use crate::rng::Rng;

/// Tokens that trigger classic bugs when they land in a string/buffer: format
/// strings, path traversal, injection, boundary dwords, overlong runs.
pub const TOKENS: &[&[u8]] = &[
    b"%n%n%n%n%n%n%n%n",
    b"%s%s%s%s%s%s%s%s",
    b"%x%x%x%x%p%p",
    b"../../../../../../../windows/win.ini",
    b"..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    b"\\\\?\\C:\\Windows\\System32",
    b"\\\\.\\pipe\\",
    b"' OR '1'='1' --",
    b"\"; DROP TABLE x;--",
    b"${jndi:ldap://127.0.0.1/a}",
    b"{{7*7}}",
    b"%00",
    b"\x00\x00\x00\x00",
    b"\xff\xff\xff\xff",
    b"\x7f\xff\xff\xff",
    b"\x80\x00\x00\x00",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    b"\r\n\r\n",
];

/// Byte values that most often flip behavior at a boundary.
const INTERESTING: &[u8] = &[
    0x00, 0x01, 0x02, 0x08, 0x0a, 0x0d, 0x1f, 0x20, 0x25, 0x2e, 0x2f, 0x40, 0x5c, 0x7e, 0x7f, 0x80,
    0xfe, 0xff,
];

/// Build a content buffer of about `len` bytes: pick a base (random / repeated
/// interesting byte / 'A' run / dictionary token), then a few havoc passes.
/// Callers that need an exact length should clamp/resize the result.
pub fn content(rng: &mut Rng, len: usize) -> Vec<u8> {
    let len = len.max(1);
    let mut b = Vec::with_capacity(len + 32);
    match rng.below(5) {
        0 => b.extend_from_slice(TOKENS[rng.pick(TOKENS.len())]),
        1 => b.resize(len, INTERESTING[rng.pick(INTERESTING.len())]),
        2 => b.resize(len, b'A'), // classic overflow probe
        _ => {
            for _ in 0..len {
                b.push((0x20 + rng.below(0x5e)) as u8);
            }
        }
    }
    while b.len() < len {
        if rng.chance(25, 100) {
            b.extend_from_slice(TOKENS[rng.pick(TOKENS.len())]);
        } else {
            b.push((0x20 + rng.below(0x5e)) as u8);
        }
    }
    bytes(rng, &mut b);
    b
}

/// Apply a handful of radamsa-style mutations to `b` in place.
pub fn bytes(rng: &mut Rng, b: &mut Vec<u8>) {
    if b.is_empty() {
        b.push(rng.next_u32() as u8);
    }
    let rounds = 1 + rng.below(6);
    for _ in 0..rounds {
        let len = b.len();
        match rng.below(9) {
            0 => {
                // bit flip
                let i = rng.pick(len);
                b[i] ^= 1u8 << rng.below(8);
            }
            1 => {
                // set an interesting byte
                let i = rng.pick(len);
                b[i] = INTERESTING[rng.pick(INTERESTING.len())];
            }
            2 => {
                // small add/sub
                let i = rng.pick(len);
                let d = 1 + rng.below(16) as u8;
                b[i] = if rng.chance(50, 100) {
                    b[i].wrapping_add(d)
                } else {
                    b[i].wrapping_sub(d)
                };
            }
            3 => {
                // insert a dictionary token
                let t = TOKENS[rng.pick(TOKENS.len())];
                let at = rng.pick(len);
                let tail = b.split_off(at);
                b.extend_from_slice(t);
                b.extend_from_slice(&tail);
            }
            4 => {
                // duplicate a chunk (grows the buffer - overflow bait)
                let n = 1 + rng.pick(len.min(64));
                let src = rng.pick(len);
                let chunk: Vec<u8> = b[src..(src + n).min(len)].to_vec();
                let at = rng.pick(len);
                let tail = b.split_off(at);
                b.extend_from_slice(&chunk);
                b.extend_from_slice(&tail);
            }
            5 => {
                // delete a chunk
                if len > 2 {
                    let n = 1 + rng.pick(len / 2);
                    let at = rng.pick(len - n);
                    b.drain(at..at + n);
                }
            }
            6 => {
                // overwrite a run with one interesting byte
                let v = INTERESTING[rng.pick(INTERESTING.len())];
                let n = 1 + rng.pick(len);
                let at = rng.pick(len);
                for k in at..(at + n).min(b.len()) {
                    b[k] = v;
                }
            }
            7 => {
                // repeat a byte many times (length blow-up)
                let v = b[rng.pick(len)];
                let n = rng.below(256) as usize;
                let at = rng.pick(len);
                let tail = b.split_off(at);
                b.resize(b.len() + n, v);
                b.extend_from_slice(&tail);
            }
            _ => {
                // swap two bytes
                let i = rng.pick(len);
                let j = rng.pick(len);
                b.swap(i, j);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_respects_hint_and_never_panics() {
        let mut rng = Rng::new(1);
        for len in [0usize, 1, 16, 64, 256, 1024] {
            for _ in 0..100 {
                let b = content(&mut rng, len);
                assert!(!b.is_empty());
            }
        }
    }

    #[test]
    fn bytes_handles_empty_and_tiny() {
        let mut rng = Rng::new(9);
        let mut v: Vec<u8> = Vec::new();
        bytes(&mut rng, &mut v);
        assert!(!v.is_empty());
        for _ in 0..500 {
            bytes(&mut rng, &mut v);
        }
    }
}
