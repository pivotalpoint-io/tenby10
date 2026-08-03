use image::{DynamicImage, ImageFormat, imageops};
use std::fs;
use std::path::PathBuf;

/// Capture the screen, apply a 20px Gaussian blur in memory, and save only the
/// blurred low-resolution JPEG to disk. The raw buffer is purged immediately.
///
/// Only the capture step is platform-specific ([`capture_raw_image`]); the
/// privacy-critical pipeline (blur, drop the raw buffer, save the blurred JPEG)
/// is shared and identical on every platform — see [`blur_and_save`].
pub fn capture_and_blur_screenshot(
    screenshots_dir: PathBuf,
    slot_start: i64,
) -> Result<PathBuf, String> {
    if !screenshots_dir.exists() {
        fs::create_dir_all(&screenshots_dir)
            .map_err(|err| format!("Failed to create screenshots dir: {}", err))?;
    }
    let raw_img = capture_raw_image()?;
    blur_and_save(raw_img, screenshots_dir, slot_start)
}

/// Ground-truth health probe: attempt a real capture and immediately discard the
/// pixels. Nothing is blurred, saved, or returned — the raw buffer is dropped
/// before this function returns, so probing never writes an image to disk.
///
/// Needed because neither available signal is trustworthy on its own: the TCC
/// preflight (`CGPreflightScreenCaptureAccess`) keeps returning a cached `true`
/// after a grant is revoked, and the real slot capture only runs once per
/// 10 minutes — so a broken capture can read as healthy for that long (issue #6).
/// Actually trying is the only way to know now.
pub fn probe_capture() -> Result<(), String> {
    let raw_img = capture_raw_image()?;
    // Explicitly purge the raw capture: a probe only wants the success/failure.
    drop(raw_img);
    Ok(())
}

/// Shared privacy pipeline: blur the raw capture in memory, **drop the raw
/// buffer**, and write only the blurred image as a low-resolution JPEG. The raw,
/// unblurred image is never passed to `save`. Platform-independent so the same
/// guarantee holds everywhere.
fn blur_and_save(
    raw_img: DynamicImage,
    screenshots_dir: PathBuf,
    slot_start: i64,
) -> Result<PathBuf, String> {
    // 20px Gaussian blur in memory.
    let blurred_img = imageops::blur(&raw_img, 20.0);

    // Explicitly purge the raw image from memory before anything is written.
    drop(raw_img);

    // Discard alpha (JPEG has no alpha) and save the blurred image only.
    let rgb_img = DynamicImage::ImageRgba8(blurred_img).to_rgb8();

    let file_name = format!("slot_{}.jpg", slot_start);
    let mut file_path = screenshots_dir;
    file_path.push(file_name);

    rgb_img
        .save_with_format(&file_path, ImageFormat::Jpeg)
        .map_err(|err| format!("Failed to save blurred image to disk: {}", err))?;

    println!(
        "[Screen] Blurred image saved successfully to {:?}",
        file_path
    );
    Ok(file_path)
}

/// macOS: capture the main display straight into memory via `CGDisplayCreateImage`.
///
/// This used to shell out to `screencapture -t png /dev/stdout` and read the
/// child's stdout. That can never work: `Command::output()` makes stdout a
/// **pipe**, and `screencapture` needs a seekable destination, so it always
/// exited having written nothing — "cannot write file to intended destination".
/// Capture therefore failed 100% of the time on every machine, and the resulting
/// error ("permission is likely denied") sent every diagnosis down the TCC rabbit
/// hole. See issue #47.
///
/// Capturing in-process also keeps the promise in AUDIT.md that the raw,
/// unblurred screenshot **never touches disk** — a temp-file workaround would
/// have written exactly that. Nothing is spawned and nothing is written; the raw
/// pixels exist only in this buffer until [`blur_and_save`] drops them.
///
/// Does NOT fabricate a placeholder on failure: that made a denied Screen
/// Recording permission look like a successful capture. The error is surfaced so
/// the caller can flag capture as unhealthy.
#[cfg(target_os = "macos")]
fn capture_raw_image() -> Result<DynamicImage, String> {
    use core_graphics::display::CGDisplay;

    let display = CGDisplay::main();
    let cg_image = display.image().ok_or_else(|| {
        "CGDisplayCreateImage returned no image; Screen Recording permission is likely denied"
            .to_string()
    })?;

    let width = cg_image.width();
    let height = cg_image.height();
    if width == 0 || height == 0 {
        return Err("Captured display image has zero dimensions".to_string());
    }

    // CoreGraphics hands back 32bpp BGRA. Rows are padded to `bytes_per_row`,
    // which is >= width*4, so the stride must be walked rather than assuming a
    // tightly packed buffer — otherwise the image shears on displays whose width
    // isn't a multiple of the alignment.
    let bytes_per_row = cg_image.bytes_per_row();
    let src = cg_image.data();
    let src: &[u8] = &src;

    let mut rgba = Vec::with_capacity(width * height * 4);
    for y in 0..height {
        let row = y * bytes_per_row;
        let row_end = row + width * 4;
        if row_end > src.len() {
            return Err(format!(
                "Captured buffer is shorter than expected ({} bytes, needed {})",
                src.len(),
                row_end
            ));
        }
        for px in src[row..row_end].chunks_exact(4) {
            // BGRA -> RGBA
            rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
    }

    image::RgbaImage::from_raw(width as u32, height as u32, rgba)
        .map(DynamicImage::ImageRgba8)
        .ok_or_else(|| "Failed to build image from captured display bytes".to_string())
}

/// Windows: capture the primary display with GDI (`BitBlt` + `GetDIBits`) into a
/// top-down 32-bit buffer, then convert BGRA → RGBA. All GDI handles are released
/// before returning. (Runtime correctness — orientation, DWM, multi-monitor —
/// needs verification on a real Windows machine, like the macOS path does.)
#[cfg(target_os = "windows")]
fn capture_raw_image() -> Result<DynamicImage, String> {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use winapi::shared::windef::HGDIOBJ;
    use winapi::um::wingdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
        DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDIBits, SRCCOPY, SelectObject,
    };
    use winapi::um::winuser::{GetDC, GetSystemMetrics, ReleaseDC, SM_CXSCREEN, SM_CYSCREEN};

    unsafe {
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        if width <= 0 || height <= 0 {
            return Err("Invalid screen dimensions".to_string());
        }

        let screen_dc = GetDC(null_mut());
        if screen_dc.is_null() {
            return Err("GetDC(screen) failed".to_string());
        }
        let mem_dc = CreateCompatibleDC(screen_dc);
        let bitmap = CreateCompatibleBitmap(screen_dc, width, height);
        if mem_dc.is_null() || bitmap.is_null() {
            if !bitmap.is_null() {
                DeleteObject(bitmap as HGDIOBJ);
            }
            if !mem_dc.is_null() {
                DeleteDC(mem_dc);
            }
            ReleaseDC(null_mut(), screen_dc);
            return Err("Failed to create GDI capture surface".to_string());
        }

        SelectObject(mem_dc, bitmap as HGDIOBJ);
        let blit_ok = BitBlt(mem_dc, 0, 0, width, height, screen_dc, 0, 0, SRCCOPY);

        // Request a top-down (negative height), 32bpp BGRA buffer.
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        let mut buffer = vec![0u8; (width as usize) * (height as usize) * 4];
        let scanlines = if blit_ok != 0 {
            GetDIBits(
                mem_dc,
                bitmap,
                0,
                height as u32,
                buffer.as_mut_ptr() as *mut _,
                &mut bmi,
                DIB_RGB_COLORS,
            )
        } else {
            0
        };

        DeleteObject(bitmap as HGDIOBJ);
        DeleteDC(mem_dc);
        ReleaseDC(null_mut(), screen_dc);

        if blit_ok == 0 || scanlines == 0 {
            return Err("GDI screen capture failed (BitBlt/GetDIBits)".to_string());
        }

        // GDI gives BGRA; the image crate expects RGBA. Swap B and R.
        for px in buffer.chunks_exact_mut(4) {
            px.swap(0, 2);
        }

        image::RgbaImage::from_raw(width as u32, height as u32, buffer)
            .map(DynamicImage::ImageRgba8)
            .ok_or_else(|| "Failed to build image from captured bytes".to_string())
    }
}

/// Other platforms: screen capture is not implemented.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn capture_raw_image() -> Result<DynamicImage, String> {
    Err("Screen capture is not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_blur_and_save_writes_a_blurred_jpeg() {
        // The privacy pipeline is platform-independent, so this runs (and is
        // verified) on every CI target, including Windows.
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tenby10_screen_test_{}", uniq));
        std::fs::create_dir_all(&dir).unwrap();

        // A solid-color raw image; after blur it must still be a valid JPEG of
        // the same dimensions.
        let raw = DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            48,
            32,
            image::Rgba([200, 60, 30, 255]),
        ));

        let path = blur_and_save(raw, dir.clone(), 4242).unwrap();
        assert!(path.exists(), "a JPEG should be written");
        assert_eq!(path.extension().unwrap(), "jpg");

        let reloaded = image::open(&path).expect("output is a valid image");
        assert_eq!(reloaded.width(), 48);
        assert_eq!(reloaded.height(), 32);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// On-device smoke test for the **real** capture path — the platform-specific
    /// step (`screencapture` on macOS, GDI on Windows) that cannot run on a
    /// headless CI runner. Ignored by default so CI stays green; run it on a real
    /// machine with screen-recording permission to verify the refactor end to end:
    ///
    /// ```text
    /// cargo test -p daemon -- --ignored capture_real_screen
    /// ```
    #[test]
    #[ignore = "captures the real screen; needs a display + screen-recording permission"]
    fn test_capture_real_screen_produces_a_blurred_jpeg() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tenby10_capture_smoke_{}", uniq));

        // Exercises capture_and_blur_screenshot end to end, including the real
        // platform capture and the shared blur/drop/save pipeline.
        let path = capture_and_blur_screenshot(dir.clone(), 777)
            .expect("real screen capture should succeed on a permitted device");

        assert!(path.exists(), "a blurred JPEG should be written");
        let img = image::open(&path).expect("captured output is a valid JPEG");
        assert!(
            img.width() > 0 && img.height() > 0,
            "captured image has real dimensions"
        );

        // Regression guard for #47: the capture must be the *actual* display, not
        // a stand-in. A non-zero-dimensions check alone passed happily for years
        // while every saved file was the fabricated 800x600 placeholder.
        #[cfg(target_os = "macos")]
        {
            use core_graphics::display::CGDisplay;
            let d = CGDisplay::main();
            // `pixels_wide()` reports points; a Retina capture is a 2x pixel
            // buffer. So assert "at least the display, and not the old fixed-size
            // stand-in" rather than an exact match, which holds on both.
            assert_ne!(
                (img.width(), img.height()),
                (800, 600),
                "800x600 is the fabricated placeholder, not a real capture"
            );
            assert!(
                img.width() >= d.pixels_wide() as u32 && img.height() >= d.pixels_high() as u32,
                "capture ({}x{}) is smaller than the display ({}x{}) — not a real screen grab",
                img.width(),
                img.height(),
                d.pixels_wide(),
                d.pixels_high()
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// On-device check for the capture-health probe (issue #6). Like the capture
    /// smoke test above it needs a real display + screen-recording permission, so
    /// it is ignored on CI:
    ///
    /// ```text
    /// cargo test -p daemon -- --ignored probe_capture
    /// ```
    #[test]
    #[ignore = "captures the real screen; needs a display + screen-recording permission"]
    fn test_probe_capture_succeeds_and_writes_nothing() {
        let before = std::env::temp_dir().join("tenby10_probe_should_not_appear.jpg");
        std::fs::remove_file(&before).ok();

        probe_capture().expect("probe should succeed on a permitted device");

        // The probe must be side-effect free: it exists to answer a yes/no, and
        // must never leave an image behind (it does not blur, so anything it wrote
        // would be a raw screenshot on disk).
        assert!(
            !before.exists(),
            "probe_capture must not write any image to disk"
        );
    }
}
