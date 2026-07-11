//! Minimal connection-oriented DCE/RPC (MS-RPCE) PDU layer.
//!
//! Enough to bind to an interface and issue calls by opnum over a stream
//! transport (`ncacn_ip_tcp` / `ncacn_np`): build BIND and REQUEST PDUs, and
//! classify the reply (BIND_ACK / RESPONSE / FAULT). This is deliberately raw -
//! it does not use the Windows RPC runtime - so the fuzzer has full control over
//! exactly what bytes go on the wire, including the malformed ones.
//!
//! Reference: DCE 1.1 RPC (connection-oriented) / [MS-RPCE] §2.2.

/// PDU types we care about.
pub mod ptype {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const BIND: u8 = 11;
    pub const BIND_ACK: u8 = 12;
    pub const BIND_NAK: u8 = 13;
    pub const AUTH3: u8 = 16;
}

/// Authentication service ids (sec_trailer `auth_type`).
pub const RPC_C_AUTHN_WINNT: u8 = 0x0a; // NTLM
/// Authentication levels (sec_trailer `auth_level`).
pub const RPC_C_AUTHN_LEVEL_CONNECT: u8 = 0x02;
pub const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: u8 = 0x05;

/// First + last fragment.
const PFC_FIRST_LAST: u8 = 0x03;

/// NDR transfer-syntax GUID (8a885d04-1ceb-11c9-9fe8-08002b104860) in wire form.
const NDR_TRANSFER_SYNTAX: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// The 16-byte common header shared by every connection-oriented PDU.
fn common_header(pkt_type: u8, frag_len: u16, call_id: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = 5; // rpc_vers
    h[1] = 0; // rpc_vers_minor
    h[2] = pkt_type;
    h[3] = PFC_FIRST_LAST;
    // packed data representation: little-endian, ASCII, IEEE float.
    h[4] = 0x10;
    h[8..10].copy_from_slice(&frag_len.to_le_bytes());
    // auth_length (10..12) = 0
    h[12..16].copy_from_slice(&call_id.to_le_bytes());
    h
}

/// Build a BIND PDU proposing one presentation context: `(interface, NDR)`.
pub fn build_bind(call_id: u32, iface_uuid: [u8; 16], ver_major: u16, ver_minor: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    body.push(1); // num_ctx_items
    body.extend_from_slice(&[0, 0, 0]); // pad

    // presentation context 0
    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0); // reserved
                  // abstract syntax = interface uuid + version
    body.extend_from_slice(&iface_uuid);
    body.extend_from_slice(&ver_major.to_le_bytes());
    body.extend_from_slice(&ver_minor.to_le_bytes());
    // transfer syntax = NDR v2.0
    body.extend_from_slice(&NDR_TRANSFER_SYNTAX);
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());

    let frag_len = (16 + body.len()) as u16;
    let mut pdu = common_header(ptype::BIND, frag_len, call_id).to_vec();
    pdu.extend_from_slice(&body);
    pdu
}

/// Append a sec_trailer (8 bytes) + auth token, aligning the body first.
/// Returns the auth token length (for the common-header `auth_length`).
fn append_auth_trailer(body: &mut Vec<u8>, auth_type: u8, auth_level: u8, token: &[u8]) -> u16 {
    // The sec_trailer begins on a 4-byte boundary within the PDU (matches the
    // Windows runtime capture: bind/auth3 use auth_pad 0..3). `auth_pad_length`
    // records how much we added.
    let pad = (4 - (body.len() % 4)) % 4;
    body.resize(body.len() + pad, 0);
    body.push(auth_type);
    body.push(auth_level);
    body.push(pad as u8); // auth_pad_length
    body.push(0); // auth_reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // auth_context_id
    body.extend_from_slice(token);
    token.len() as u16
}

/// Like [`build_bind`] but carrying an authentication token (first leg).
pub fn build_bind_auth(
    call_id: u32,
    iface_uuid: [u8; 16],
    ver_major: u16,
    ver_minor: u16,
    auth_type: u8,
    auth_level: u8,
    token: &[u8],
) -> Vec<u8> {
    let mut plain = build_bind(call_id, iface_uuid, ver_major, ver_minor);
    let mut body = plain.split_off(16); // drop the header; rebuild it with auth_length
    let auth_len = append_auth_trailer(&mut body, auth_type, auth_level, token);

    let frag_len = (16 + body.len()) as u16;
    let mut pdu = common_header(ptype::BIND, frag_len, call_id).to_vec();
    pdu[10..12].copy_from_slice(&auth_len.to_le_bytes());
    pdu.extend_from_slice(&body);
    pdu
}

/// Build the AUTH3 PDU (third leg) carrying the final auth token.
pub fn build_auth3(call_id: u32, auth_type: u8, auth_level: u8, token: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 4]; // 4-byte pad field
    let auth_len = append_auth_trailer(&mut body, auth_type, auth_level, token);

    let frag_len = (16 + body.len()) as u16;
    let mut pdu = common_header(ptype::AUTH3, frag_len, call_id).to_vec();
    pdu[10..12].copy_from_slice(&auth_len.to_le_bytes());
    pdu.extend_from_slice(&body);
    pdu
}

/// Build a REQUEST PDU protected at PKT_INTEGRITY: the stub is padded to a
/// 16-byte multiple, then `sign` produces the 16-byte auth token over
/// `header || stub_padded || sec_trailer`. Layout on the wire:
/// `common(16) | req_hdr(8) | stub | pad | sec_trailer(8) | token(16)`.
pub fn build_request_signed(
    call_id: u32,
    opnum: u16,
    context_id: u16,
    stub: &[u8],
    auth_type: u8,
    auth_level: u8,
    sign: impl FnOnce(&[u8], &mut [u8], &[u8]) -> std::io::Result<Vec<u8>>,
) -> std::io::Result<Vec<u8>> {
    // The stub is padded to a 16-byte multiple, and the pad bytes ARE part of
    // the signed message (PKT_INTEGRITY protects the whole PDU body up to the
    // sec_trailer). `auth_pad_length` in the trailer tells the receiver how many.
    let auth_pad = (16 - (stub.len() % 16)) % 16;

    const AUTH_LEN: u16 = 16;
    let frag_len = (16 + 8 + stub.len() + auth_pad + 8 + AUTH_LEN as usize) as u16;

    // header = common header (16) + request header (8), signed read-only.
    let mut header = common_header(ptype::REQUEST, frag_len, call_id).to_vec();
    header[10..12].copy_from_slice(&AUTH_LEN.to_le_bytes());
    header.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint (unpadded)
    header.extend_from_slice(&context_id.to_le_bytes());
    header.extend_from_slice(&opnum.to_le_bytes());

    // sec_trailer (8 bytes), also signed read-only.
    let sec_trailer = [
        auth_type,
        auth_level,
        auth_pad as u8,
        0, // reserved
        0,
        0,
        0,
        0, // auth_context_id = 0 (consistent with the bind)
    ];

    // Sign the stub + auth pad as one DATA buffer. For PKT_PRIVACY this buffer
    // would be encrypted in place; for PKT_INTEGRITY it's unchanged.
    let mut stub_signed = stub.to_vec();
    stub_signed.resize(stub_signed.len() + auth_pad, 0);
    let token = sign(&header, &mut stub_signed, &sec_trailer)?;

    let mut pdu = header;
    pdu.extend_from_slice(&stub_signed); // stub + pad (already on the wire)
    pdu.extend_from_slice(&sec_trailer);
    pdu.extend_from_slice(&token);
    Ok(pdu)
}

/// Extract the server's auth token (the trailing `auth_length` bytes) from a
/// reply PDU such as BIND_ACK.
pub fn extract_auth_token(pdu: &[u8]) -> Option<&[u8]> {
    if pdu.len() < 12 {
        return None;
    }
    let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    if auth_len == 0 {
        return None;
    }
    let start = pdu.len().checked_sub(auth_len)?;
    Some(&pdu[start..])
}

/// Build a REQUEST PDU carrying `stub` (our marshaled NDR) for `opnum`.
pub fn build_request(call_id: u32, opnum: u16, context_id: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    body.extend_from_slice(&context_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(stub);

    let frag_len = (16 + body.len()) as u16;
    let mut pdu = common_header(ptype::REQUEST, frag_len, call_id).to_vec();
    pdu.extend_from_slice(&body);
    pdu
}

/// Parsed common header fields we act on.
#[derive(Debug, Clone, Copy)]
pub struct PduHeader {
    pub pkt_type: u8,
    pub frag_length: u16,
}

/// Parse the 16-byte common header. Returns `None` if it isn't a v5 PDU.
pub fn parse_header(buf: &[u8]) -> Option<PduHeader> {
    if buf.len() < 16 || buf[0] != 5 {
        return None;
    }
    Some(PduHeader {
        pkt_type: buf[2],
        frag_length: u16::from_le_bytes([buf[8], buf[9]]),
    })
}

/// The DCE fault status code from a FAULT PDU body, if present. A fault is a
/// server-side rejection/exception - an interesting fuzz signal.
pub fn fault_status(pdu: &[u8]) -> Option<u32> {
    // header(16) + alloc_hint(4) + context_id(2) + cancel_count(1) + pad(1)
    // then status(4).
    let off = 24;
    pdu.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Parse a canonical UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) into
/// the 16-byte on-wire GUID form (Data1/2/3 little-endian, Data4 as-is).
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for i in 0..16 {
        let hi = (hex[i * 2] as char).to_digit(16)?;
        let lo = (hex[i * 2 + 1] as char).to_digit(16)?;
        raw[i] = ((hi << 4) | lo) as u8;
    }
    // raw is big-endian textual order; convert Data1(4)/Data2(2)/Data3(2).
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    out[4..6].copy_from_slice(&[raw[5], raw[4]]);
    out[6..8].copy_from_slice(&[raw[7], raw[6]]);
    out[8..16].copy_from_slice(&raw[8..16]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_pdu_shape() {
        let uuid = parse_uuid("a1b2c3d4-1111-2222-3333-444455556666").unwrap();
        let b = build_bind(1, uuid, 1, 0);
        assert_eq!(b[0], 5); // rpc v5
        assert_eq!(b[2], ptype::BIND);
        assert_eq!(b[3], PFC_FIRST_LAST);
        // frag_length matches total.
        assert_eq!(u16::from_le_bytes([b[8], b[9]]) as usize, b.len());
        // abstract-syntax UUID: header(16) + max_xmit/recv(4) + assoc(4) +
        // num_ctx(1) + pad(3) + p_cont_id(2) + n_transfer(1) + reserved(1) = 32.
        assert_eq!(&b[32..48], &uuid);
    }

    #[test]
    fn request_pdu_carries_opnum_and_stub() {
        let stub = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let r = build_request(7, 3, 0, &stub);
        assert_eq!(r[2], ptype::REQUEST);
        assert_eq!(u32::from_le_bytes([r[12], r[13], r[14], r[15]]), 7); // call_id
        assert_eq!(u32::from_le_bytes([r[16], r[17], r[18], r[19]]), 4); // alloc_hint
        assert_eq!(u16::from_le_bytes([r[22], r[23]]), 3); // opnum
        assert_eq!(&r[24..28], &stub); // stub data
    }

    #[test]
    fn uuid_roundtrip_wire_form() {
        // Known: IID_IUnknown 00000000-0000-0000-c000-000000000046
        let w = parse_uuid("00000000-0000-0000-c000-000000000046").unwrap();
        assert_eq!(&w[8..16], &[0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
    }
}
