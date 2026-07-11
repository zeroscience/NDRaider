//! JSON payload generation + mutation for services that carry a JSON command
//! *inside* an RPC byte buffer - "JSON-over-RPC". Lenovo Vantage is the
//! motivating example (its `byte[size_is]` in/out params carry JSON), but the
//! pattern is common.
//!
//! Raw byte mutation of a JSON buffer just yields invalid JSON the handler
//! rejects, so structure-aware fuzzing here is what actually reaches the command
//! handlers (the layer where injection / path-traversal / logic bugs live).
//! Two modes:
//!   * **synthesize** - build random-but-valid JSON with fuzz payloads in
//!     string/number/key positions;
//!   * **mutate a seed** - walk a real captured JSON request and perturb values
//!     (best, if you have example requests via `--seeds`).

use crate::rng::Rng;
use serde_json::{Map, Value};

/// Nasty string payloads: SQLi, path traversal, template/expr injection, nulls,
/// format specifiers, registry paths (the classes seen in real IPC bugs).
const INJECT: &[&str] = &[
    "",
    "A",
    "true",
    "null",
    "' OR '1'='1",
    "'; DROP TABLE Settings;--",
    "\" OR \"\"=\"",
    "../../../../../../Windows/win.ini",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "\\\\?\\C:\\Windows\\System32",
    "file:///C:/Windows/win.ini",
    "%00",
    "{{7*7}}",
    "${jndi:ldap://127.0.0.1/x}",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "C:\\Windows\\System32\\cmd.exe",
    "%n%n%n%n%s%s%s%s",
    "-1",
    "4294967296",
];

fn payload(rng: &mut Rng) -> String {
    match rng.below(14) {
        0..=8 => INJECT[rng.pick(INJECT.len())].to_string(),
        // Overlong, but bounded so the whole JSON usually still fits an inline
        // LRPC message (~0xF00 bytes) instead of being skipped as too big.
        9 | 10 => "A".repeat(1 + rng.below(3000) as usize),
        11 => format!("{}", rng.next_u64() as i64),
        _ => {
            let n = rng.below(24) as usize;
            (0..n)
                .map(|_| (0x20 + rng.below(0x5e) as u8) as char)
                .collect()
        }
    }
}

/// Field names commonly seen in JSON-RPC / settings commands (incl. the ones
/// called out in the Vantage advisory: `Component`, `localSetting`).
fn key(rng: &mut Rng) -> String {
    const KEYS: &[&str] = &[
        "method",
        "id",
        "params",
        "component",
        "Component",
        "localSetting",
        "name",
        "value",
        "path",
        "key",
        "action",
        "command",
        "data",
        "type",
        "version",
        "payload",
        "args",
        "query",
        "setting",
    ];
    KEYS[rng.pick(KEYS.len())].to_string()
}

fn synth(rng: &mut Rng, depth: u32) -> Value {
    if depth == 0 {
        return Value::String(payload(rng));
    }
    match rng.below(10) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 1),
        2 => Value::Number((rng.next_u64() as i64).into()),
        3..=5 => Value::String(payload(rng)),
        6..=7 => {
            let n = rng.below(4);
            Value::Array((0..n).map(|_| synth(rng, depth - 1)).collect())
        }
        _ => {
            let mut m = Map::new();
            for _ in 0..(1 + rng.below(4)) {
                m.insert(key(rng), synth(rng, depth - 1));
            }
            Value::Object(m)
        }
    }
}

/// Perturb a parsed JSON value in place: replace strings/numbers with payloads,
/// occasionally add keys/elements or type-confuse.
fn mutate(v: &mut Value, rng: &mut Rng) {
    match v {
        Value::String(s) => {
            if rng.chance(65, 100) {
                *s = payload(rng);
            }
        }
        Value::Number(_) => {
            if rng.chance(50, 100) {
                *v = Value::Number((rng.next_u64() as i64).into());
            }
        }
        Value::Bool(b) => {
            if rng.chance(30, 100) {
                *b = !*b;
            }
        }
        Value::Array(a) => {
            for e in a.iter_mut() {
                mutate(e, rng);
            }
            if rng.chance(20, 100) {
                a.push(synth(rng, 2));
            }
        }
        Value::Object(m) => {
            let keys: Vec<String> = m.keys().cloned().collect();
            for k in keys {
                if let Some(val) = m.get_mut(&k) {
                    mutate(val, rng);
                }
            }
            if rng.chance(25, 100) {
                m.insert(key(rng), synth(rng, 2));
            }
            // Occasionally type-confuse a value into a nested object/array.
            if rng.chance(10, 100) {
                if let Some(k) = m.keys().next().cloned() {
                    m.insert(k, synth(rng, 2));
                }
            }
        }
        Value::Null => {
            if rng.chance(20, 100) {
                *v = Value::String(payload(rng));
            }
        }
    }
}

/// Produce a JSON payload as UTF-8 bytes: mutate a random seed if any are
/// provided, otherwise synthesize one.
pub fn json_bytes(rng: &mut Rng, seeds: &[Value]) -> Vec<u8> {
    let v = if !seeds.is_empty() {
        let mut c = seeds[rng.pick(seeds.len())].clone();
        mutate(&mut c, rng);
        c
    } else {
        synth(rng, 3)
    };
    serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_is_valid_json() {
        let mut rng = Rng::new(1);
        for _ in 0..200 {
            let b = json_bytes(&mut rng, &[]);
            // Must round-trip as valid JSON.
            serde_json::from_slice::<Value>(&b).expect("synth produced invalid JSON");
        }
    }

    #[test]
    fn mutates_a_seed() {
        let seed: Value =
            serde_json::json!({"method":"getSetting","params":{"Component":"battery"}});
        let mut rng = Rng::new(7);
        let b = json_bytes(&mut rng, std::slice::from_ref(&seed));
        serde_json::from_slice::<Value>(&b).expect("mutated seed still valid JSON");
    }
}
