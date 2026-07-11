//! C ABI surface for non-Rust consumers (the Binary Ninja plugin, primarily).
//!
//! The contract is intentionally tiny and string-based: hand in a path, get
//! back a JSON [`crate::Report`] as a NUL-terminated UTF-8 string that the
//! caller must release with [`ndr_string_free`]. Keeping the boundary at "bytes
//! in, JSON out" means the plugin never has to mirror Rust structs - it just
//! `json.loads()` the result.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Analyze the PE at `path` and return a newly-allocated JSON string describing
/// the [`crate::Report`]. Returns `NULL` on any error (bad UTF-8 path, I/O
/// failure, parse failure, or a panic caught at the boundary).
///
/// # Safety
/// `path` must be a valid NUL-terminated C string. The returned pointer, if
/// non-NULL, must be freed exactly once with [`ndr_string_free`].
#[no_mangle]
pub unsafe extern "C" fn ndr_analyze_path_json(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = CStr::from_ptr(path).to_str().ok()?;
        let report = crate::analyze_path(path).ok()?;
        let json = serde_json::to_string(&report).ok()?;
        CString::new(json).ok()
    }));

    match result {
        Ok(Some(cstr)) => cstr.into_raw(),
        _ => std::ptr::null_mut(),
    }
}

/// Free a string returned by [`ndr_analyze_path_json`].
///
/// # Safety
/// `s` must be either NULL or a pointer previously returned by this library and
/// not yet freed. Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn ndr_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Return the library version string (semver from Cargo). Statically allocated;
/// do **not** free it.
#[no_mangle]
pub extern "C" fn ndr_version() -> *const c_char {
    // Compile-time NUL-terminated; safe to hand out as a borrowed pointer.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
