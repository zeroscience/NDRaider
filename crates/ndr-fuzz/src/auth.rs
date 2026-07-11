//! Client-side NTLM via Windows SSPI, for authenticating DCE/RPC binds.
//!
//! Windows faults unauthenticated `ncacn_ip_tcp`/`ncacn_np` calls with
//! ACCESS_DENIED before dispatch, so to actually reach (and fuzz) handler code
//! we run the standard 3-leg NTLM handshake mapped onto RPC's bind / bind_ack /
//! auth3 PDUs. We use the caller's default credentials and auth level CONNECT
//! (authenticate the connection; requests then carry no per-PDU auth trailer).

#[cfg(windows)]
pub use imp::Ntlm;

#[cfg(windows)]
mod imp {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, InitializeSecurityContextW, MakeSignature, SecBuffer,
        SecBufferDesc, SECBUFFER_DATA, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND,
    };
    use windows_sys::Win32::Security::Credentials::SecHandle;

    const SEC_E_OK: i32 = 0;
    const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312u32 as i32;
    const SECURITY_NATIVE_DREP: u32 = 0x10;
    const ISC_REQ_CONNECTION: u32 = 0x0000_0008;
    const ISC_REQ_USE_DCE_STYLE: u32 = 0x0000_0200;
    const ISC_REQ_INTEGRITY: u32 = 0x0001_0000;
    const ISC_REQ_CONFIDENTIALITY: u32 = 0x0000_0010;
    #[allow(dead_code)]
    const ISC_REQ_CONFIDENTIALITY_UNUSED: u32 = ISC_REQ_CONFIDENTIALITY;
    const ISC_REQ_FLAGS: u32 = ISC_REQ_CONNECTION | ISC_REQ_USE_DCE_STYLE | ISC_REQ_INTEGRITY;

    // Buffer type flag: included in the signature MAC but not modified.
    const SECBUFFER_READONLY_WITH_CHECKSUM: u32 = 0x1000_0000;
    // QOP: sign only, do not encrypt (PKT_INTEGRITY).
    const SECQOP_WRAP_NO_ENCRYPT: u32 = 0x8000_0001;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A minimal NTLM outbound context that emits DCE/RPC-compatible tokens.
    pub struct Ntlm {
        cred: SecHandle,
        ctx: SecHandle,
        have_ctx: bool,
        out: Vec<u8>,
    }

    impl Ntlm {
        /// Acquire an NTLM credential handle for the current user.
        pub fn new() -> Result<Self, i32> {
            let mut cred = SecHandle {
                dwLower: 0,
                dwUpper: 0,
            };
            let pkg = wide("NTLM");
            let st = unsafe {
                AcquireCredentialsHandleW(
                    null(),
                    pkg.as_ptr(),
                    SECPKG_CRED_OUTBOUND,
                    null(),
                    null(),
                    None,
                    null(),
                    &mut cred,
                    null_mut(),
                )
            };
            if st != SEC_E_OK {
                return Err(st);
            }
            Ok(Ntlm {
                cred,
                ctx: SecHandle {
                    dwLower: 0,
                    dwUpper: 0,
                },
                have_ctx: false,
                out: vec![0u8; 64 * 1024],
            })
        }

        /// Advance the handshake. `input` is the server token (None for leg 1).
        /// Returns `(output_token, continue_needed)`.
        pub fn step(&mut self, input: Option<&[u8]>) -> Result<(Vec<u8>, bool), i32> {
            let mut out_buf = SecBuffer {
                cbBuffer: self.out.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: self.out.as_mut_ptr() as *mut _,
            };
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut out_buf,
            };

            // Keep the input buffer alive for the duration of the call.
            let mut in_buf;
            let in_desc;
            let p_input: *const SecBufferDesc = match input {
                Some(tok) => {
                    in_buf = SecBuffer {
                        cbBuffer: tok.len() as u32,
                        BufferType: SECBUFFER_TOKEN,
                        pvBuffer: tok.as_ptr() as *mut _,
                    };
                    in_desc = SecBufferDesc {
                        ulVersion: SECBUFFER_VERSION,
                        cBuffers: 1,
                        pBuffers: &mut in_buf,
                    };
                    &in_desc
                }
                None => null(),
            };

            let mut attrs: u32 = 0;
            let p_ctx: *const SecHandle = if self.have_ctx { &self.ctx } else { null() };
            let st = unsafe {
                InitializeSecurityContextW(
                    &self.cred,
                    p_ctx,
                    null(), // target name: NTLM local, none required
                    ISC_REQ_FLAGS,
                    0,
                    SECURITY_NATIVE_DREP,
                    p_input,
                    0,
                    &mut self.ctx,
                    &mut out_desc,
                    &mut attrs,
                    null_mut(),
                )
            };
            self.have_ctx = true;
            if st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED {
                return Err(st);
            }
            let n = out_buf.cbBuffer as usize;
            Ok((self.out[..n].to_vec(), st == SEC_I_CONTINUE_NEEDED))
        }

        /// Produce the per-request auth token (16-byte NTLM MAC) for
        /// PKT_INTEGRITY. The stub is signed in place (unchanged - not
        /// encrypted); `header` and `trailer` are covered by the checksum. The
        /// RPCE buffer order is: header (readonly+checksum), stub (data),
        /// sec_trailer (readonly+checksum), token (output).
        pub fn sign_request(
            &mut self,
            seq_num: u32,
            header: &[u8],
            stub: &mut [u8],
            trailer: &[u8],
        ) -> Result<Vec<u8>, i32> {
            let mut token = vec![0u8; 16];
            let mut bufs = [
                SecBuffer {
                    cbBuffer: header.len() as u32,
                    BufferType: SECBUFFER_DATA | SECBUFFER_READONLY_WITH_CHECKSUM,
                    pvBuffer: header.as_ptr() as *mut _,
                },
                SecBuffer {
                    cbBuffer: stub.len() as u32,
                    BufferType: SECBUFFER_DATA,
                    pvBuffer: stub.as_mut_ptr() as *mut _,
                },
                SecBuffer {
                    cbBuffer: trailer.len() as u32,
                    BufferType: SECBUFFER_DATA | SECBUFFER_READONLY_WITH_CHECKSUM,
                    pvBuffer: trailer.as_ptr() as *mut _,
                },
                SecBuffer {
                    cbBuffer: token.len() as u32,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: token.as_mut_ptr() as *mut _,
                },
            ];
            let desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 4,
                pBuffers: bufs.as_mut_ptr(),
            };
            // PKT_INTEGRITY: MakeSignature checksums the DATA + read-only buffers
            // and writes the 16-byte MAC into the TOKEN buffer (no encryption).
            // The buffers are updated through the raw pointers in `desc`.
            let _ = SECQOP_WRAP_NO_ENCRYPT;
            let st = unsafe { MakeSignature(&self.ctx, 0, &desc, seq_num) };
            if st != SEC_E_OK {
                return Err(st);
            }
            token.truncate(bufs[3].cbBuffer as usize);
            Ok(token)
        }
    }
}
