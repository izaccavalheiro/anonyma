#![deny(unsafe_op_in_unsafe_fn)]

//! The C ABI. Strings cross it as NUL-terminated UTF-8; results are owned by
//! the caller, who frees them with [`anonyma_string_free`].

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use anonyma_core::InMemoryVault;

use crate::api::call_json_with_vault;

/// A token vault owned by the caller: tokens issued by `shield` and restored
/// by `restore` through [`anonyma_vault_call`]. It holds original values in
/// clear; free it when the conversation ends.
pub struct AnonymaVault {
    inner: InMemoryVault,
}

fn error_json(message: &str) -> *mut c_char {
    let text = serde_json::json!({ "error": message }).to_string();
    CString::new(text).map_or(ptr::null_mut(), CString::into_raw)
}

/// # Safety
///
/// `text` is null or a NUL-terminated string valid for the call.
unsafe fn read<'a>(text: *const c_char, name: &str) -> Result<&'a str, String> {
    if text.is_null() {
        return Err(format!("{name} is null"));
    }
    // SAFETY: the caller passes a NUL-terminated string (see above).
    unsafe { CStr::from_ptr(text) }
        .to_str()
        .map_err(|_| format!("{name} is not UTF-8"))
}

fn respond(result: String) -> *mut c_char {
    // JSON text never holds a NUL byte: serde_json escapes U+0000.
    CString::new(result).map_or_else(|_| error_json("NUL in result"), CString::into_raw)
}

/// # Safety
///
/// See [`anonyma_call`].
unsafe fn dispatch(
    vault: Option<&mut InMemoryVault>,
    op: *const c_char,
    input: *const c_char,
) -> *mut c_char {
    // SAFETY: forwarded from the caller's contract.
    let arguments =
        unsafe { read(op, "op").and_then(|op| read(input, "input").map(|input| (op, input))) };
    let (op, input) = match arguments {
        Ok(pair) => pair,
        Err(message) => return error_json(&message),
    };
    match catch_unwind(AssertUnwindSafe(|| call_json_with_vault(op, input, vault))) {
        Ok(result) => respond(result),
        Err(_) => error_json("internal error"),
    }
}

/// Perform the operation `op` (`detect`, `anonymize`, `validate`, ...) on
/// `input_json`. Returns `{"ok": ...}` or `{"error": ...}`; free it with
/// [`anonyma_string_free`].
///
/// # Safety
///
/// `op` and `input_json` are null or NUL-terminated strings valid for the call.
#[no_mangle]
pub unsafe extern "C" fn anonyma_call(op: *const c_char, input_json: *const c_char) -> *mut c_char {
    // SAFETY: the caller's contract is this function's.
    unsafe { dispatch(None, op, input_json) }
}

/// A new, empty token vault. Free it with [`anonyma_vault_free`].
#[no_mangle]
pub extern "C" fn anonyma_vault_new() -> *mut AnonymaVault {
    Box::into_raw(Box::new(AnonymaVault {
        inner: InMemoryVault::new(),
    }))
}

/// [`anonyma_call`] with a vault: `shield` stores its tokens in it and
/// `restore` reads them from it.
///
/// # Safety
///
/// `vault` comes from [`anonyma_vault_new`], is not freed, and is not used by
/// another thread during the call; the strings are as for [`anonyma_call`].
#[no_mangle]
pub unsafe extern "C" fn anonyma_vault_call(
    vault: *mut AnonymaVault,
    op: *const c_char,
    input_json: *const c_char,
) -> *mut c_char {
    if vault.is_null() {
        return error_json("vault is null");
    }
    // SAFETY: a live vault owned by the caller, used by this thread only.
    let vault = unsafe { &mut (*vault).inner };
    // SAFETY: forwarded from the caller's contract.
    unsafe { dispatch(Some(vault), op, input_json) }
}

/// Free a vault and every value it holds.
///
/// # Safety
///
/// `vault` is null or comes from [`anonyma_vault_new`] and is not used again.
#[no_mangle]
pub unsafe extern "C" fn anonyma_vault_free(vault: *mut AnonymaVault) {
    if !vault.is_null() {
        // SAFETY: allocated by anonyma_vault_new and given back once.
        drop(unsafe { Box::from_raw(vault) });
    }
}

/// Free a string returned by this library.
///
/// # Safety
///
/// `text` is null or a string returned by this library, not freed before.
#[no_mangle]
pub unsafe extern "C" fn anonyma_string_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: allocated by CString::into_raw in this library.
        drop(unsafe { CString::from_raw(text) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(vault: *mut AnonymaVault, op: &str, input: &str) -> String {
        let op = CString::new(op).unwrap();
        let input = CString::new(input).unwrap();
        // SAFETY: valid strings and vault for the duration of the call.
        unsafe {
            let out = if vault.is_null() {
                anonyma_call(op.as_ptr(), input.as_ptr())
            } else {
                anonyma_vault_call(vault, op.as_ptr(), input.as_ptr())
            };
            let text = CStr::from_ptr(out).to_str().unwrap().to_string();
            anonyma_string_free(out);
            text
        }
    }

    #[test]
    fn round_trip_through_the_c_abi() {
        let vault = anonyma_vault_new();
        let shielded = call(
            vault,
            "shield",
            r#"{"text":"Mail ann@example.com","categories":["email"]}"#,
        );
        assert!(shielded.contains("{{EMAIL_1}}"), "{shielded}");
        let restored = call(vault, "restore", r#"{"text":"Hi {{EMAIL_1}}"}"#);
        assert!(restored.contains("Hi ann@example.com"), "{restored}");
        // SAFETY: allocated above, not used again.
        unsafe { anonyma_vault_free(vault) };
    }

    #[test]
    fn null_arguments_are_errors() {
        // SAFETY: null pointers are accepted and reported.
        unsafe {
            let out = anonyma_call(ptr::null(), ptr::null());
            assert!(CStr::from_ptr(out).to_str().unwrap().contains("op is null"));
            anonyma_string_free(out);
            let out = anonyma_vault_call(ptr::null_mut(), ptr::null(), ptr::null());
            assert!(CStr::from_ptr(out)
                .to_str()
                .unwrap()
                .contains("vault is null"));
            anonyma_string_free(out);
        }
    }
}
