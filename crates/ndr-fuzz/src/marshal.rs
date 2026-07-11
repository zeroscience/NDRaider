//! A pragmatic NDR (DCE, classic transfer syntax) marshaler.
//!
//! Serializes a [`Value`] tree into the request stub-data bytes. It implements
//! the common wire rules - little-endian, natural alignment, conformant
//! `max_count` prefixes, unique-pointer referent ids, conformant-string
//! max/offset/actual headers - which cover the great majority of real method
//! parameters. It is deliberately NOT a byte-perfect NDR engine: full
//! conformance *hoisting* for deeply nested conformant structs is simplified
//! (documented in NDR_NOTES / README). The point is buffers that are valid
//! enough to reach server code, plus the deliberate malformations the generator
//! injects.

use crate::value::Value;

pub struct Marshaler {
    buf: Vec<u8>,
    next_referent: u32,
}

impl Marshaler {
    pub fn new() -> Self {
        Marshaler {
            buf: Vec::new(),
            next_referent: 0x0002_0000,
        }
    }

    /// Marshal an ordered list of top-level request field values.
    pub fn marshal_fields(mut self, fields: &[&Value]) -> Vec<u8> {
        for v in fields {
            self.value(v);
        }
        self.buf
    }

    fn align(&mut self, a: usize) {
        if a <= 1 {
            return;
        }
        // `is_multiple_of` isn't on our MSRV yet; keep the explicit modulo.
        #[allow(clippy::manual_is_multiple_of)]
        while self.buf.len() % a != 0 {
            self.buf.push(0);
        }
    }

    fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn value(&mut self, v: &Value) {
        match v {
            Value::Scalar { bytes, data } => {
                let a = (*bytes as usize).clamp(1, 8);
                self.align(a);
                self.buf
                    .extend_from_slice(&data.to_le_bytes()[..*bytes as usize]);
            }
            Value::Blob(b) => {
                // Context handles etc. are 4-aligned on the wire.
                self.align(4);
                self.buf.extend_from_slice(b);
            }
            Value::UniquePtr(inner) => match inner {
                None => self.u32(0),
                Some(p) => {
                    let id = self.next_referent;
                    self.next_referent = self.next_referent.wrapping_add(4);
                    self.u32(id);
                    self.value(p);
                }
            },
            Value::RefPtr(p) => self.value(p),
            Value::Array {
                max_count,
                varying,
                offset,
                actual,
                elements,
            } => {
                // Conformant (and varying) array header, then elements.
                self.u32(*max_count);
                if *varying {
                    self.u32(*offset);
                    self.u32(*actual);
                }
                for e in elements {
                    self.value(e);
                }
            }
            Value::FixedArray(elements) => {
                for e in elements {
                    self.value(e);
                }
            }
            Value::ConfStr {
                unit_size,
                count,
                bytes,
            } => {
                // NDR conformant string: max_count, offset(0), actual_count.
                self.u32(*count);
                self.u32(0);
                self.u32(*count);
                self.align(*unit_size as usize);
                self.buf.extend_from_slice(bytes);
            }
            Value::Struct(members) => {
                for m in members {
                    self.value(m);
                }
            }
            Value::Union {
                tag_bytes,
                tag,
                arm,
            } => {
                let a = (*tag_bytes as usize).clamp(1, 8);
                self.align(a);
                self.buf
                    .extend_from_slice(&tag.to_le_bytes()[..*tag_bytes as usize]);
                if let Some(arm) = arm {
                    self.value(arm);
                }
            }
        }
    }
}

impl Default for Marshaler {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: marshal a slice of owned values.
pub fn marshal(values: &[Value]) -> Vec<u8> {
    let refs: Vec<&Value> = values.iter().collect();
    Marshaler::new().marshal_fields(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_alignment() {
        // u8 then u32: the u32 must be 4-aligned (3 pad bytes inserted).
        let v = vec![
            Value::Scalar {
                bytes: 1,
                data: 0xAA,
            },
            Value::Scalar {
                bytes: 4,
                data: 0x1122_3344,
            },
        ];
        let b = marshal(&v);
        assert_eq!(b[0], 0xAA);
        assert_eq!(&b[4..8], &[0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn conformant_array_has_maxcount_prefix() {
        let arr = Value::Array {
            max_count: 3,
            varying: false,
            offset: 0,
            actual: 3,
            elements: vec![
                Value::Scalar { bytes: 4, data: 1 },
                Value::Scalar { bytes: 4, data: 2 },
                Value::Scalar { bytes: 4, data: 3 },
            ],
        };
        let b = marshal(&[arr]);
        // max_count (3) first, then the three longs.
        assert_eq!(&b[0..4], &3u32.to_le_bytes());
        assert_eq!(&b[4..8], &1u32.to_le_bytes());
        assert_eq!(b.len(), 4 + 12);
    }

    #[test]
    fn null_unique_pointer_is_zero_referent() {
        let b = marshal(&[Value::UniquePtr(None)]);
        assert_eq!(b, vec![0, 0, 0, 0]);
    }
}
