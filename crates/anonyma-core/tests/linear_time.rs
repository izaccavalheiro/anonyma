//! Detection allocates in proportion to the text, not to the text times the
//! number of candidates.
//!
//! A case-insensitive pattern reads an ASCII-lower-cased copy of the text. That
//! copy used to be made again for every candidate of a search loop, so a long
//! text with capitals and many labelled values cost O(text × candidates) time
//! and memory. This test counts the bytes allocated by one detection on such a
//! text: with the copy made once per pattern, the total stays a small multiple
//! of the text's length.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use anonyma_core::{AnonymaEngine, Category};

/// The system allocator, counting the bytes it hands out.
struct Counting;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded unchanged to the system allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.fetch_add(new_size, Ordering::Relaxed);
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Bytes allocated while `f` runs. The counter is global, so this binary holds
/// one test: no other thread allocates meanwhile.
fn allocated_by<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATED.load(Ordering::Relaxed);
    let out = f();
    (out, ALLOCATED.load(Ordering::Relaxed) - before)
}

/// `count` labelled addresses, IBANs, greetings and phone numbers, with capitals
/// throughout (synthetic values only).
fn adversarial(count: usize) -> String {
    let mut text = String::new();
    for i in 0..count {
        text.push_str(&format!(
            "Shipped To: {} Example Street, Springfield. Dear Ana Example, \
             call (555) 010-{:04} or pay GB82 WEST 1234 5698 7654 32.\n",
            100 + i % 900,
            i % 10_000,
        ));
    }
    text
}

#[test]
fn allocation_grows_with_the_text_not_with_the_candidates() {
    let engine = AnonymaEngine::builder()
        .categories([
            Category::Address,
            Category::Name,
            Category::Phone,
            Category::Iban,
        ])
        .build()
        .expect("the categories are supported");
    // Warm the lazily compiled patterns, so their allocations are not counted.
    engine.detect(&adversarial(2));

    let text = adversarial(1_000);
    let (matches, bytes) = allocated_by(|| engine.detect(&text));

    assert!(matches.len() >= 3_000, "found {} matches", matches.len());
    // A copy of the text per candidate allocates about 1,000 times the text;
    // one copy per pattern and the matches themselves stay far below 64 times.
    assert!(
        bytes < 64 * text.len(),
        "allocated {bytes} bytes for a text of {} bytes",
        text.len()
    );
}
