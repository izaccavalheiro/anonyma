#![deny(unsafe_op_in_unsafe_fn)]

//! The C ABI. Strings cross it as NUL-terminated UTF-8; results are owned by
//! the caller, who frees them with [`anonyma_string_free`].

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use anonyma_core::InMemoryVault;

use crate::api::{call_engine_json, call_json_with_vault, engine_json};

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

/// An engine built once from options and kept by the caller: each call skips
/// parsing the options and building the detectors. It may be shared by
/// threads.
pub struct AnonymaEngine {
    inner: anonyma_core::AnonymaEngine,
}

/// Build an engine from JSON options (`categories`, `preset`, `rules`,
/// `defaultStrategy`, `aggressive`, `strict`, `allowPartial`). On failure,
/// returns null and, when `error` is not null, stores in it an error JSON
/// string to free with [`anonyma_string_free`].
///
/// # Safety
///
/// `options_json` is null or a NUL-terminated string valid for the call;
/// `error` is null or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn anonyma_engine_new(
    options_json: *const c_char,
    error: *mut *mut c_char,
) -> *mut AnonymaEngine {
    // SAFETY: the caller passes a valid string or null.
    let built = unsafe { read(options_json, "options") }.and_then(|options| {
        catch_unwind(AssertUnwindSafe(|| engine_json(options)))
            .unwrap_or_else(|_| Err("internal error".to_string()))
    });
    match built {
        Ok(inner) => Box::into_raw(Box::new(AnonymaEngine { inner })),
        Err(message) => {
            if !error.is_null() {
                // SAFETY: the caller passes a pointer valid for a write.
                unsafe { *error = error_json(&message) };
            }
            ptr::null_mut()
        }
    }
}

/// Perform an engine operation: `detect` and `anonymize` on `input.text`,
/// `detect_batch` and `anonymize_batch` on `input.texts` (short texts are
/// scanned together); `offsets` as in [`anonyma_call`].
///
/// # Safety
///
/// `engine` is null or returned by [`anonyma_engine_new`] and not freed;
/// `op` and `input_json` are null or NUL-terminated strings valid for the call.
#[no_mangle]
pub unsafe extern "C" fn anonyma_engine_call(
    engine: *const AnonymaEngine,
    op: *const c_char,
    input_json: *const c_char,
) -> *mut c_char {
    if engine.is_null() {
        return error_json("engine is null");
    }
    // SAFETY: a live engine from anonyma_engine_new.
    let engine = unsafe { &(*engine).inner };
    // SAFETY: the caller passes valid strings or null.
    let arguments =
        unsafe { read(op, "op").and_then(|op| read(input_json, "input").map(|input| (op, input))) };
    let (op, input) = match arguments {
        Ok(pair) => pair,
        Err(message) => return error_json(&message),
    };
    match catch_unwind(AssertUnwindSafe(|| call_engine_json(engine, op, input))) {
        Ok(result) => respond(result),
        Err(_) => error_json("internal error"),
    }
}

/// Free an engine.
///
/// # Safety
///
/// `engine` is null or returned by [`anonyma_engine_new`], not freed before.
#[no_mangle]
pub unsafe extern "C" fn anonyma_engine_free(engine: *mut AnonymaEngine) {
    if !engine.is_null() {
        // SAFETY: allocated by Box::into_raw in anonyma_engine_new.
        drop(unsafe { Box::from_raw(engine) });
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

    fn engine_call(engine: *const AnonymaEngine, op: &str, input: &str) -> String {
        let op = CString::new(op).unwrap();
        let input = CString::new(input).unwrap();
        // SAFETY: valid strings and engine for the duration of the call.
        unsafe {
            let out = anonyma_engine_call(engine, op.as_ptr(), input.as_ptr());
            let text = CStr::from_ptr(out).to_str().unwrap().to_string();
            anonyma_string_free(out);
            text
        }
    }

    #[test]
    fn an_engine_handle_detects_and_anonymizes_texts_and_batches() {
        let options = CString::new(r#"{"categories":["email"]}"#).unwrap();
        // SAFETY: a valid string; the error pointer may be null.
        let engine = unsafe { anonyma_engine_new(options.as_ptr(), ptr::null_mut()) };
        assert!(!engine.is_null());
        let one = engine_call(engine, "detect", r#"{"text":"José ana@example.com"}"#);
        assert!(one.contains(r#""start":5"#), "{one}");
        let batch = engine_call(
            engine,
            "detect_batch",
            r#"{"texts":["José ana@example.com","none"],"offsets":"bytes"}"#,
        );
        assert!(
            batch.contains(r#""start":6"#) && batch.contains(r#""matches":[]"#),
            "{batch}"
        );
        let anonymized = engine_call(
            engine,
            "anonymize_batch",
            r#"{"texts":["a ana@example.com"]}"#,
        );
        assert!(anonymized.contains("a [REDACTED]"), "{anonymized}");
        let single = engine_call(engine, "anonymize", r#"{"text":"b ana@example.com"}"#);
        assert!(single.contains("b [REDACTED]"), "{single}");
        assert!(engine_call(engine, "nope", "{}").contains("unknown engine operation"));
        assert!(engine_call(engine, "detect_batch", r#"{"texts":"x"}"#).contains("must be a list"));
        assert!(engine_call(engine, "detect", "not json").contains("not JSON"));
        // SAFETY: allocated above, not used again.
        unsafe { anonyma_engine_free(engine) };
    }

    #[test]
    fn engine_options_that_fail_report_an_error() {
        let options = CString::new(r#"{"categories":["nope"]}"#).unwrap();
        let mut error: *mut c_char = ptr::null_mut();
        // SAFETY: valid string and error pointer.
        unsafe {
            let engine = anonyma_engine_new(options.as_ptr(), &mut error);
            assert!(engine.is_null());
            assert!(CStr::from_ptr(error).to_str().unwrap().contains("error"));
            anonyma_string_free(error);
            assert!(anonyma_engine_new(ptr::null(), ptr::null_mut()).is_null());
            let out = anonyma_engine_call(ptr::null(), ptr::null(), ptr::null());
            assert!(CStr::from_ptr(out)
                .to_str()
                .unwrap()
                .contains("engine is null"));
            anonyma_string_free(out);
            let bad = CString::new("not json").unwrap();
            assert!(anonyma_engine_new(bad.as_ptr(), ptr::null_mut()).is_null());
            anonyma_engine_free(ptr::null_mut());
        }
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
