//! Input provenance — event-source discrimination (macOS tap, Windows hooks).
//!
//! On **macOS**, real hardware input reports `kCGEventSourceStateHIDSystemState`,
//! while software-injected events (`CGEventPost` — jiggler apps, simple macros)
//! do not. A listen-only `CGEventTap` reads that field per event and counts
//! synthetic vs genuine input.
//!
//! On **Windows**, low-level `WH_KEYBOARD_LL` / `WH_MOUSE_LL` hooks read the
//! `LLKHF_INJECTED` / `LLMHF_INJECTED` flag — an explicit "this event was
//! synthesized" bit (a stronger signal than the macOS inference). Both feed the
//! same counters and the same observe-only policy below.
//!
//! **Observe-first (ADR 0002 anti-automation addendum).** This *detects and
//! surfaces* injected input; it does not by itself mark a minute tampered unless
//! enforcement is explicitly enabled (`enforce_synthetic_detection`, default
//! off). Two reasons:
//!   1. The tap's runtime behavior cannot be verified in CI, and a bad field read
//!      would falsely flag genuine typists — the worst failure for the product.
//!   2. Legitimate tools (text expanders, password-manager auto-type) also post
//!      synthetic events. The enforcement rule that avoids punishing them —
//!      "the minute had input but *zero* genuine hardware events" — still needs
//!      on-device red-team calibration before it is trusted — the fixture
//!      corpus and trace-capture tooling that gate needs are tracked in #119.
//!
//! **Honest limits.** A hardware HID emulator (Teensy/QMK) posts genuine HID
//! events, and a sophisticated injector can spoof the source state — both evade.
//! This is a speed bump against naive injection, not a wall.

use std::sync::atomic::{AtomicU64, Ordering};

/// `kCGEventSourceStateHIDSystemState` — events originating from real hardware.
const HID_SYSTEM_STATE_ID: i64 = 1;

/// `kCGEventSourceStateID` field selector. core-graphics 0.22 does not expose a
/// named constant, but the field accessor takes a raw `u32`.
#[cfg(target_os = "macos")]
const CG_EVENT_SOURCE_STATE_ID: u32 = 45;

static SYNTHETIC_EVENTS: AtomicU64 = AtomicU64::new(0);
static GENUINE_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Whether an event's source-state id indicates software injection rather than
/// real HID hardware.
pub fn is_synthetic_source(source_state_id: i64) -> bool {
    source_state_id != HID_SYSTEM_STATE_ID
}

/// Whether an interval's input was *entirely* injected: at least one synthetic
/// event and **zero** genuine hardware events — the pure-automation signature.
/// A real person touching their keyboard or mouse always produces genuine
/// events, so this never fires for them, even if they also use a text expander.
pub fn all_input_injected(synthetic: u64, genuine: u64) -> bool {
    synthetic > 0 && genuine == 0
}

/// Read and reset this interval's `(synthetic, genuine)` input event counts.
pub fn take_counts() -> (u64, u64) {
    (
        SYNTHETIC_EVENTS.swap(0, Ordering::Relaxed),
        GENUINE_EVENTS.swap(0, Ordering::Relaxed),
    )
}

/// Start the background provenance tap. macOS-only (matches the screen-capture
/// path); a no-op elsewhere. Fails open: if the tap or run-loop source cannot be
/// created, it logs and returns so nothing is ever counted as synthetic.
#[cfg(target_os = "macos")]
pub fn start_provenance_monitor() {
    use core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
    use core_graphics::event::{
        CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType,
        CallbackResult,
    };

    std::thread::spawn(|| {
        let events = vec![
            CGEventType::KeyDown,
            CGEventType::KeyUp,
            CGEventType::LeftMouseDown,
            CGEventType::LeftMouseUp,
            CGEventType::RightMouseDown,
            CGEventType::RightMouseUp,
            CGEventType::OtherMouseDown,
            CGEventType::OtherMouseUp,
            CGEventType::MouseMoved,
            CGEventType::LeftMouseDragged,
            CGEventType::RightMouseDragged,
            CGEventType::ScrollWheel,
        ];

        let tap = CGEventTap::new(
            CGEventTapLocation::HID,
            CGEventTapPlacement::HeadInsertEventTap,
            CGEventTapOptions::ListenOnly,
            events,
            |_proxy, _type, event| {
                let state = event.get_integer_value_field(CG_EVENT_SOURCE_STATE_ID);
                if is_synthetic_source(state) {
                    SYNTHETIC_EVENTS.fetch_add(1, Ordering::Relaxed);
                } else {
                    GENUINE_EVENTS.fetch_add(1, Ordering::Relaxed);
                }
                CallbackResult::Keep // listen-only: pass the event through unchanged
            },
        );

        let tap = match tap {
            Ok(tap) => tap,
            Err(()) => {
                eprintln!(
                    "[Provenance] Could not create the input-provenance tap \
                     (needs Input Monitoring). Synthetic-input detection is disabled for this run."
                );
                return; // fail open — no counts, no false flags
            }
        };

        let source = match tap.mach_port().create_runloop_source(0) {
            Ok(source) => source,
            Err(()) => {
                eprintln!("[Provenance] Could not create the run-loop source; detection disabled.");
                return;
            }
        };

        let run_loop = CFRunLoop::get_current();
        // Keep `tap` alive on this stack for the lifetime of the run loop: it owns
        // the callback the tap invokes. `run_current` blocks until stopped.
        run_loop.add_source(&source, unsafe { kCFRunLoopDefaultMode });
        tap.enable();
        CFRunLoop::run_current();
    });
}

// --- Windows: low-level hooks read the explicit injected flag ---
//
// `WH_KEYBOARD_LL` / `WH_MOUSE_LL` deliver `KBDLLHOOKSTRUCT` / `MSLLHOOKSTRUCT`
// whose `flags` carry `LLKHF_INJECTED` / `LLMHF_INJECTED` — a *direct* "this
// event was synthesized" bit, a stronger signal than macOS's source-state
// inference. Same observe-only design and honest limit (a hardware HID emulator
// posts non-injected events and evades).

/// `LLKHF_INJECTED` — keyboard event was injected. Defined locally rather than
/// relying on the winapi export.
#[cfg(target_os = "windows")]
const LLKHF_INJECTED: winapi::shared::minwindef::DWORD = 0x0000_0010;
/// `LLMHF_INJECTED` — mouse event was injected.
#[cfg(target_os = "windows")]
const LLMHF_INJECTED: winapi::shared::minwindef::DWORD = 0x0000_0001;

#[cfg(target_os = "windows")]
unsafe extern "system" fn keyboard_hook(
    code: std::os::raw::c_int,
    wparam: winapi::shared::minwindef::WPARAM,
    lparam: winapi::shared::minwindef::LPARAM,
) -> winapi::shared::minwindef::LRESULT {
    use winapi::um::winuser::{CallNextHookEx, HC_ACTION, KBDLLHOOKSTRUCT};
    if code == HC_ACTION {
        let info = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
        if info.flags & LLKHF_INJECTED != 0 {
            SYNTHETIC_EVENTS.fetch_add(1, Ordering::Relaxed);
        } else {
            GENUINE_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    }
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn mouse_hook(
    code: std::os::raw::c_int,
    wparam: winapi::shared::minwindef::WPARAM,
    lparam: winapi::shared::minwindef::LPARAM,
) -> winapi::shared::minwindef::LRESULT {
    use winapi::um::winuser::{CallNextHookEx, HC_ACTION, MSLLHOOKSTRUCT};
    if code == HC_ACTION {
        let info = unsafe { &*(lparam as *const MSLLHOOKSTRUCT) };
        if info.flags & LLMHF_INJECTED != 0 {
            SYNTHETIC_EVENTS.fetch_add(1, Ordering::Relaxed);
        } else {
            GENUINE_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    }
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

/// Start the background provenance monitor on Windows: install low-level
/// keyboard/mouse hooks and pump a message loop (the hooks fire while the thread
/// is blocked in `GetMessageW`). Fails open if the hooks cannot be installed.
#[cfg(target_os = "windows")]
pub fn start_provenance_monitor() {
    use winapi::um::winuser::{GetMessageW, MSG, SetWindowsHookExW, WH_KEYBOARD_LL, WH_MOUSE_LL};
    std::thread::spawn(|| unsafe {
        let kb = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), std::ptr::null_mut(), 0);
        let ms = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), std::ptr::null_mut(), 0);
        if kb.is_null() && ms.is_null() {
            eprintln!(
                "[Provenance] Could not install Windows input hooks. \
                 Synthetic-input detection is disabled for this run."
            );
            return; // fail open — no counts, no false flags
        }
        // Low-level hooks are dispatched to this thread while it blocks in the
        // message pump; no message ever returns for a windowless thread, so this
        // keeps the thread alive and the hooks live.
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {}
    });
}

/// Other platforms: provenance discrimination is unavailable.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn start_provenance_monitor() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_synthetic_source() {
        assert!(!is_synthetic_source(1)); // HIDSystemState = real hardware
        assert!(is_synthetic_source(0)); // CombinedSessionState = injected
        assert!(is_synthetic_source(-1)); // Private = injected
        assert!(is_synthetic_source(2)); // anything else = injected
    }

    #[test]
    fn test_all_input_injected() {
        assert!(
            all_input_injected(5, 0),
            "input, none of it genuine -> injected"
        );
        assert!(
            !all_input_injected(5, 3),
            "some genuine input -> not flagged"
        );
        assert!(!all_input_injected(0, 0), "no input at all -> not flagged");
        assert!(!all_input_injected(0, 5), "all genuine -> not flagged");
    }
}
