//! Embed the application/file icon (logo.png -> .ico) into ndr-gui.exe so it
//! shows the logo in Explorer, the taskbar, and when pinned - not just the
//! runtime window icon. Best-effort: if the resource compiler isn't available,
//! we warn and continue (the runtime `with_icon` still works).

fn main() {
    #[cfg(windows)]
    embed_icon();
}

#[cfg(windows)]
fn embed_icon() {
    let png = "../../logo.png";
    println!("cargo:rerun-if-changed={png}");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let ico_path = std::path::Path::new(&out_dir).join("logo.ico");

    let Ok(dyn_img) = image::open(png) else {
        println!("cargo:warning=logo.png not found; skipping exe icon");
        return;
    };
    let rgba = dyn_img.to_rgba8();
    let (w, h) = rgba.dimensions();

    // Bounding box of non-transparent pixels.
    let (mut minx, mut miny, mut maxx, mut maxy) = (w, h, 0u32, 0u32);
    let mut any = false;
    for y in 0..h {
        for x in 0..w {
            if rgba.get_pixel(x, y)[3] > 12 {
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
    let (cw, ch) = (maxx - minx + 1, maxy - miny + 1);

    // Center the warm-tinted crop in a square canvas with a small margin.
    let content = cw.max(ch);
    let side = content + content / 8;
    let ox = (side - cw) / 2;
    let oy = (side - ch) / 2;
    let mut sq = image::RgbaImage::new(side, side);
    for y in 0..ch {
        for x in 0..cw {
            let px = rgba.get_pixel(minx + x, miny + y);
            sq.put_pixel(
                ox + x,
                oy + y,
                image::Rgba([
                    (px[0] as f32 * 1.35).min(255.0) as u8,
                    (px[1] as f32 * 1.02).min(255.0) as u8,
                    (px[2] as f32 * 0.5) as u8,
                    px[3],
                ]),
            );
        }
    }
    let icon = image::imageops::resize(&sq, 256, 256, image::imageops::FilterType::Lanczos3);

    // Encode a single 256x256 .ico.
    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    let img = ico::IconImage::from_rgba_data(256, 256, icon.into_raw());
    match ico::IconDirEntry::encode(&img) {
        Ok(entry) => dir.add_entry(entry),
        Err(e) => {
            println!("cargo:warning=ico encode failed: {e}");
            return;
        }
    }
    let Ok(file) = std::fs::File::create(&ico_path) else {
        println!("cargo:warning=could not write logo.ico");
        return;
    };
    if dir.write(file).is_err() {
        println!("cargo:warning=could not serialize logo.ico");
        return;
    }

    // Embed it into the PE.
    let mut res = winresource::WindowsResource::new();
    res.set_icon(ico_path.to_str().unwrap());
    if let Err(e) = res.compile() {
        println!("cargo:warning=icon embed skipped (no resource compiler?): {e}");
    }
}
