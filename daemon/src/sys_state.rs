#[cfg(target_os = "macos")]
pub fn is_locked_or_asleep() -> bool {
    use std::panic;

    // Use catch_unwind to provide defensive programming against unexpected panics in unsafe code
    let result = panic::catch_unwind(|| {
        #[link(name = "CoreGraphics", kind = "framework")]
        unsafe extern "C" {
            fn CGSessionCopyCurrentDictionary() -> *mut std::ffi::c_void;
            fn CGMainDisplayID() -> u32;
            fn CGDisplayIsAsleep(display: u32) -> u32;
        }

        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn CFDictionaryGetValue(
                dict: *mut std::ffi::c_void,
                key: *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            fn CFStringCreateWithCString(
                alloc: *mut std::ffi::c_void,
                c_str: *const i8,
                encoding: u32,
            ) -> *mut std::ffi::c_void;
            fn CFBooleanGetValue(boolean: *mut std::ffi::c_void) -> bool;
            fn CFRelease(cf: *mut std::ffi::c_void);
        }

        unsafe {
            // 1. Check Display Sleep State
            let display_id = CGMainDisplayID();
            if CGDisplayIsAsleep(display_id) != 0 {
                return true;
            }

            // 2. Check Session Lock State
            let dict = CGSessionCopyCurrentDictionary();
            if dict.is_null() {
                // Defensive: No UI session dict usually means locked/asleep or login screen
                return true;
            }

            let key_str = std::ffi::CString::new("CGSSessionScreenIsLocked").unwrap_or_default();
            if key_str.as_bytes().is_empty() {
                CFRelease(dict);
                return false; // Fallback safely
            }

            // 0x08000100 is kCFStringEncodingUTF8
            let key = CFStringCreateWithCString(std::ptr::null_mut(), key_str.as_ptr(), 0x08000100);

            if key.is_null() {
                CFRelease(dict);
                return false;
            }

            let mut is_locked = false;
            let val = CFDictionaryGetValue(dict, key);
            if !val.is_null() {
                is_locked = CFBooleanGetValue(val);
            }

            CFRelease(key);
            CFRelease(dict);

            is_locked
        }
    });

    // Fallback gracefully to `false` if any panic occurs in the FFI boundary
    result.unwrap_or(false)
}

#[cfg(target_os = "windows")]
pub fn is_locked_or_asleep() -> bool {
    // Windows logic: We check the active window name inside the main loop instead
    // (e.g. "LockApp.exe", "LogonUI.exe")
    false
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn is_locked_or_asleep() -> bool {
    // Linux/Other fallback
    false
}
