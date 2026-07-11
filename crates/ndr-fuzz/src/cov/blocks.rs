//! Static basic-block discovery for coverage instrumentation.
//!
//! We approximate basic-block *leaders* (the first instruction of each block)
//! by linearly disassembling the executable sections and collecting:
//!   * the section start,
//!   * the target of every direct branch/call,
//!   * the instruction after every control-flow instruction (branch/call/ret).
//!
//! The set is over-approximate (a `jmp`'s fall-through is treated as a leader
//! even if unreachable) which is fine - more instrumentation points means finer
//! coverage. Targets that don't land on a decoded instruction boundary (data,
//! other modules) are dropped. Addresses are **RVAs** (offsets from the module
//! base), so the debugger just adds the runtime base.

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use ndr_core::pe::PeImage;
use std::collections::BTreeSet;

/// Compute basic-block leader RVAs for every code (`.text`) section of `pe`.
pub fn block_rvas(pe: &PeImage) -> Vec<u32> {
    let bits = if pe.is_64bit { 64 } else { 32 };
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    let mut valid: BTreeSet<u32> = BTreeSet::new();

    // Pass 1: decode each code section, gather raw leaders + valid instr starts.
    for (sec, bytes) in pe.section_slices() {
        if !is_code_section(&sec.name) {
            continue;
        }
        // Section bytes on disk may be shorter than the virtual size; only the
        // raw bytes are real instructions.
        let n = (sec.raw_size as usize).min(bytes.len());
        leaders_in(
            &bytes[..n],
            sec.virtual_address,
            bits,
            &mut leaders,
            &mut valid,
        );
    }

    // Pass 2: keep only leaders that land on a real instruction boundary.
    leaders.intersection(&valid).copied().collect()
}

fn is_code_section(name: &str) -> bool {
    // MIDL server stubs and handlers live in .text; some toolchains split code
    // into .text$xx merged as .text. Accept the common code section names.
    name == ".text" || name.starts_with(".text") || name == "CODE"
}

/// Core, test-friendly leader finder over a flat code buffer whose first byte is
/// at `base_rva`. Fills `leaders` (candidate block starts) and `valid` (every
/// decoded instruction's RVA).
fn leaders_in(
    code: &[u8],
    base_rva: u32,
    bits: u32,
    leaders: &mut BTreeSet<u32>,
    valid: &mut BTreeSet<u32>,
) {
    if code.is_empty() {
        return;
    }
    leaders.insert(base_rva);
    let mut decoder = Decoder::new(bits, code, DecoderOptions::NONE);
    decoder.set_ip(base_rva as u64);
    let mut instr = iced_x86::Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let ip = instr.ip() as u32;
        valid.insert(ip);
        let next = instr.next_ip() as u32;
        match instr.flow_control() {
            FlowControl::Next => {}
            FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call => {
                // Direct near control flow: both the target and the following
                // instruction start new blocks.
                let t = instr.near_branch_target();
                if t != 0 {
                    leaders.insert(t as u32);
                }
                leaders.insert(next);
            }
            // Indirect flow / returns / interrupts: only the fall-through (which
            // for ret/jmp indirect is the next block, e.g. a switch tail).
            _ => {
                leaders.insert(next);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_conditional_branch_blocks() {
        // xor eax,eax; test ecx,ecx; je +3; inc eax; ret; dec rax; ret
        let code = [
            0x31, 0xC0, // 0x1000 xor eax,eax
            0x85, 0xC9, // 0x1002 test ecx,ecx
            0x74, 0x03, // 0x1004 je 0x1009
            0xFF, 0xC0, // 0x1006 inc eax
            0xC3, // 0x1008 ret
            0x48, 0xFF, 0xC8, // 0x1009 dec rax
            0xC3, // 0x100C ret
        ];
        let mut leaders = BTreeSet::new();
        let mut valid = BTreeSet::new();
        leaders_in(&code, 0x1000, 64, &mut leaders, &mut valid);
        let got: Vec<u32> = leaders.intersection(&valid).copied().collect();
        // section start, je fall-through, je target.
        assert_eq!(got, vec![0x1000, 0x1006, 0x1009]);
    }

    #[test]
    fn empty_is_empty() {
        let mut l = BTreeSet::new();
        let mut v = BTreeSet::new();
        leaders_in(&[], 0x2000, 64, &mut l, &mut v);
        assert!(l.is_empty());
    }
}
