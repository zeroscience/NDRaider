//! NDRaider GUI (codename: Sani) - a visual front-end over `ndr-cli` / `ndr-fuzz`.
//!
//! It doesn't reimplement anything: it builds the right command lines, runs the
//! existing binaries, streams their output live, and turns the results into
//! panels - sweep -> select a target -> tune options -> fuzz -> watch the pulse.
//!
//! Powered by Silly Security Inc. (https://sillysec.com) & Zero Science Lab
//! (https://zeroscience.mk).

#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod runner;

use app::NdrGuiApp;

/// The app/window icon: logo.png, cropped to its non-transparent content (so the
/// mark fills the icon and reads larger) and warm-tinted to match the UI.
fn load_icon() -> Option<eframe::egui::IconData> {
    let bytes = include_bytes!("../../../logo.png");
    let img = image::load_from_memory(bytes).ok()?.to_rgba8();
    let (w, h) = img.dimensions();
    let src = img.into_raw();

    // Bounding box of non-transparent pixels.
    let (mut minx, mut miny, mut maxx, mut maxy) = (w, h, 0u32, 0u32);
    let mut any = false;
    for y in 0..h {
        for x in 0..w {
            if src[((y * w + x) * 4 + 3) as usize] > 12 {
                any = true;
                minx = minx.min(x);
                maxx = maxx.max(x);
                miny = miny.min(y);
                maxy = maxy.max(y);
            }
        }
    }
    if !any {
        minx = 0;
        miny = 0;
        maxx = w - 1;
        maxy = h - 1;
    }
    let cw = maxx - minx + 1;
    let ch = maxy - miny + 1;

    // Center the (warm-tinted) crop in a SQUARE canvas with a small margin -
    // Windows icons must be square, else it falls back to the default icon.
    let content = cw.max(ch);
    let side = content + content / 8; // ~6% margin each side
    let ox = (side - cw) / 2;
    let oy = (side - ch) / 2;
    let mut out = vec![0u8; (side * side * 4) as usize];
    for y in 0..ch {
        for x in 0..cw {
            let si = (((miny + y) * w + (minx + x)) * 4) as usize;
            let di = (((oy + y) * side + (ox + x)) * 4) as usize;
            out[di] = (src[si] as f32 * 1.35).min(255.0) as u8;
            out[di + 1] = (src[si + 1] as f32 * 1.02).min(255.0) as u8;
            out[di + 2] = (src[si + 2] as f32 * 0.5) as u8;
            out[di + 3] = src[si + 3];
        }
    }
    Some(eframe::egui::IconData {
        rgba: out,
        width: side,
        height: side,
    })
}

fn main() -> eframe::Result<()> {
    let bits = if cfg!(target_pointer_width = "64") { "64" } else { "32" };
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1260.0, 860.0])
        .with_min_inner_size([940.0, 620.0])
        .with_title(format!("NDRaider (Win{bits})"));
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "NDRaider",
        native_options,
        Box::new(|cc| Ok(Box::new(NdrGuiApp::new(cc)))),
    )
}
