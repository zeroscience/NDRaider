//! NDRaider GUI - "friendly yo" edition. One button scans the system for
//! worthwhile fuzzable RPC/DCOM components, lists them in a sortable two-tone
//! table, click one for an overview + fuzz style, hit Fuzz. Coffee-cat palette.

use eframe::egui::{self, Color32, RichText};
use std::collections::VecDeque;
use std::path::PathBuf;

use crate::runner::{self, Job, Msg};

// ---- coffee-cat palette ----
const INK: Color32 = Color32::from_rgb(26, 23, 18); // black lines / text
const YELLOW: Color32 = Color32::from_rgb(224, 167, 43); // main golden background
const YELLOW_ALT: Color32 = Color32::from_rgb(206, 148, 30); // alternate row
const COFFEE: Color32 = Color32::from_rgb(90, 58, 32); // headers / accent
const CREAM: Color32 = Color32::from_rgb(244, 233, 205); // buttons / inputs
const SEL: Color32 = Color32::from_rgb(245, 214, 138); // selected row highlight

// ---------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Rpc,
    Dcom,
}

fn type_label(k: Kind) -> &'static str {
    match k {
        Kind::Rpc => "RPC",
        Kind::Dcom => "DCOM",
    }
}

#[derive(Clone)]
struct Component {
    path: String,   // file path (RPC) or CLSID (COM/DCOM)
    name: String,   // display name
    server: String, // backing file: the PE (RPC) or the COM server exe (DCOM)
    arch: String,
    interfaces: u64,
    methods: u64,
    kind: Kind,
}

#[derive(PartialEq, Clone, Copy)]
enum SortKey {
    Name,
    Ifaces,
    Methods,
    Arch,
}

#[derive(PartialEq, Clone, Copy)]
enum FuzzStyle {
    Standard,
    Json,
    Coverage,
}

#[derive(PartialEq, Clone, Copy)]
enum JobKind {
    Sweep,
    ComList,
    Fuzz,
    None,
}

enum Action {
    ScanSystem,
    ScanApps,
    ScanCom,
    ScanDir,
    Select(String),
    Sort(SortKey),
    Fuzz,
    Stop,
    ClearLog,
    BrowseOut,
    OpenLoc(String),
    PageHeap(bool),
}

/// Suggest a fuzz style for a component from simple heuristics.
fn suggest(c: &Component) -> (&'static str, FuzzStyle, Color32) {
    if c.kind == Kind::Dcom {
        // COM/DCOM objects are fuzzed via IDispatch::Invoke.
        return ("Dispatch", FuzzStyle::Standard, Color32::from_rgb(40, 70, 120));
    }
    let p = c.path.to_ascii_lowercase();
    if p.contains("vantage") || p.contains("addin") || p.contains("lenovo") {
        // JSON-over-RPC services carry a JSON command in a byte[] buffer.
        ("JSON", FuzzStyle::Json, Color32::from_rgb(120, 78, 42))
    } else if c.arch == "x64" {
        // x64 can be block-instrumented for coverage feedback.
        ("Coverage", FuzzStyle::Coverage, Color32::from_rgb(30, 100, 60))
    } else {
        // x86/WOW64: coverage is crash-detect only, so plain structure-aware.
        ("Standard", FuzzStyle::Standard, Color32::from_rgb(90, 58, 32))
    }
}

// ---------------------------------------------------------------------------
// Pulse: a field of colored pixels that spawn on activity and dissolve away.
// ---------------------------------------------------------------------------

struct Pulse {
    samples: VecDeque<f32>,
    level: f32,
    y: f32,
    phase: f32,
    seed: u64,
    cap: usize,
}

impl Pulse {
    fn new() -> Self {
        let cap = 160;
        Pulse {
            samples: VecDeque::from(vec![0.0_f32; cap]),
            level: 0.0,
            y: 0.0,
            phase: 0.0,
            seed: 0x2545_F491_4F6C_DD1D,
            cap,
        }
    }

    fn rnd(&mut self) -> f32 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 40) as f32 / (1u64 << 24) as f32
    }

    /// Each fuzzed message bumps the amplitude - more data = wilder swings.
    fn beat(&mut self, amp: f32) {
        self.level = (self.level + amp).min(1.0);
    }

    /// A brown lie-detector line: a jittery pen whose up/down swing scales with
    /// how much data is flying. `crashed` turns the background red; `label`
    /// ("Scanning"/"Fuzzing") rides on top.
    fn draw(&mut self, ui: &mut egui::Ui, active: bool, crashed: bool, label: &str, size: egui::Vec2) {
        self.phase += 0.30;
        let base = if active { 0.10 } else { 0.02 };
        let amp = (base + self.level).min(1.0);
        // polygraph pen: chase a random target (scaled by activity) with a bit
        // of momentum + a slow baseline wander, so idle = flat, busy = thrashing.
        let target = (self.rnd() * 2.0 - 1.0) * amp;
        let wander = (self.phase * 0.5).sin() * 0.10 * amp;
        self.y = self.y * 0.55 + (target + wander) * 0.45;
        self.samples.push_back(self.y.clamp(-1.0, 1.0));
        while self.samples.len() > self.cap {
            self.samples.pop_front();
        }
        self.level *= 0.90;

        let (rect, _r) = ui.allocate_exact_size(size, egui::Sense::hover());
        let p = ui.painter_at(rect);
        let bg = if crashed {
            Color32::from_rgb(160, 32, 28)
        } else {
            Color32::from_rgb(236, 202, 108)
        };
        p.rect_filled(rect, 4.0, bg);

        let n = self.samples.len().max(2);
        let dx = rect.width() / (n as f32 - 1.0);
        let mid = rect.center().y;
        let half = rect.height() * 0.40;
        let pts: Vec<_> = self
            .samples
            .iter()
            .enumerate()
            .map(|(i, v)| egui::pos2(rect.left() + dx * i as f32, mid - v * half))
            .collect();
        let line = if crashed {
            Color32::from_rgb(250, 225, 215)
        } else {
            Color32::from_rgb(108, 64, 30) // brown, the most visible element
        };
        p.add(egui::Shape::line(pts, egui::Stroke::new(2.3, line)));

        // Glass reflection: a soft top sheen + two diagonal glare streaks, like
        // the curved glass over an old radio dial.
        let (w, h) = (rect.width(), rect.height());
        let sheen = egui::Rect::from_min_max(
            rect.left_top(),
            egui::pos2(rect.right(), rect.top() + h * 0.40),
        );
        p.rect_filled(sheen, 4.0, Color32::from_rgba_unmultiplied(255, 255, 255, 26));
        let streak = |p0: f32, wid: f32, a: u8| {
            let x = rect.left() + w * p0;
            p.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(x, rect.top()),
                    egui::pos2(x + w * wid, rect.top()),
                    egui::pos2(x + w * wid - w * 0.10, rect.bottom()),
                    egui::pos2(x - w * 0.10, rect.bottom()),
                ],
                Color32::from_rgba_unmultiplied(255, 255, 255, a),
                egui::Stroke::NONE,
            ));
        };
        streak(0.16, 0.055, 30);
        streak(0.26, 0.028, 22);

        if !label.is_empty() {
            // Lower-right, below the line: small, dark, and breathing while active.
            let base = if crashed {
                Color32::from_rgb(255, 232, 224)
            } else {
                Color32::from_rgb(60, 38, 14) // dark coffee - readable + sexy
            };
            let alpha = if active {
                let t = 0.5 + 0.5 * (self.phase * 0.6).sin();
                (140.0 + 115.0 * t) as u8
            } else {
                215
            };
            let c = Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), alpha);
            p.text(
                rect.right_bottom() + egui::vec2(-6.0, 1.0),
                egui::Align2::RIGHT_BOTTOM,
                label,
                egui::FontId::proportional(11.0),
                c,
            );
        }
    }
}

#[derive(Default)]
struct Stats {
    cases: u64,
    responses: u64,
    faults: u64,
    crashes: u64,
}

// ---------------------------------------------------------------------------

pub struct NdrGuiApp {
    cli_path: String,
    fuzz_path: String,

    components: Vec<Component>,
    selected: Option<String>,
    detected: String,
    filter: String,
    scan_queue: Vec<String>,
    sort: SortKey,
    sort_desc: bool,

    count: u32,
    style: FuzzStyle,
    out_dir: String,
    repros: usize,
    show_settings: bool,
    show_about: bool,
    scroll_crash: bool,
    zoom: f32,

    job: Option<Job>,
    job_kind: JobKind,
    json_buf: String,
    log: VecDeque<String>,
    status: String,
    stats: Stats,
    pulse: Pulse,
    cat: Option<CatTex>,
}

/// A loaded cat texture plus the UV sub-rect of its non-transparent content and
/// that content's aspect ratio - so we can bottom-anchor the *visible* cat
/// (ignoring the PNG's transparent padding).
struct CatTex {
    tex: egui::TextureHandle,
    uv: egui::Rect,
    aspect: f32,
}

/// Load `catgui.png` at runtime (next to the exe, or cwd) so the build doesn't
/// depend on the file existing. Trims the transparent margin. Falls back to a
/// drawn cat if absent.
fn load_cat(ctx: &egui::Context) -> Option<CatTex> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            candidates.push(d.join("catgui.png"));
        }
    }
    candidates.push(std::path::PathBuf::from("catgui.png"));
    for path in candidates {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(img) = image::load_from_memory(&bytes) else { continue };
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        let data = rgba.as_raw();

        // Bounding box of pixels that aren't (near-)transparent.
        let (mut minx, mut miny, mut maxx, mut maxy) = (w, h, 0u32, 0u32);
        let mut any = false;
        for y in 0..h {
            for x in 0..w {
                let a = data[((y * w + x) * 4 + 3) as usize];
                if a > 12 {
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
        let uv = egui::Rect::from_min_max(
            egui::pos2(minx as f32 / w as f32, miny as f32 / h as f32),
            egui::pos2((maxx + 1) as f32 / w as f32, (maxy + 1) as f32 / h as f32),
        );
        let cw = (maxx - minx + 1) as f32;
        let ch = (maxy - miny + 1) as f32;
        let ci = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], data);
        let tex = ctx.load_texture("catgui", ci, egui::TextureOptions::LINEAR);
        return Some(CatTex {
            tex,
            uv,
            aspect: cw / ch,
        });
    }
    None
}

impl NdrGuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let mut style = (*cc.egui_ctx.style()).clone();

        for (ts, sz) in [
            (egui::TextStyle::Heading, 19.0),
            (egui::TextStyle::Body, 14.0),
            (egui::TextStyle::Button, 14.0),
            (egui::TextStyle::Monospace, 13.0),
            (egui::TextStyle::Small, 11.5),
        ] {
            let fam = if ts == egui::TextStyle::Monospace {
                egui::FontFamily::Monospace
            } else {
                egui::FontFamily::Proportional
            };
            style.text_styles.insert(ts, egui::FontId::new(sz, fam));
        }
        style.spacing.button_padding = egui::vec2(9.0, 4.0);
        style.spacing.item_spacing = egui::vec2(6.0, 5.0);

        // Palette: golden panels, black text, cream buttons, two-tone rows.
        let v = &mut style.visuals;
        v.panel_fill = YELLOW;
        v.faint_bg_color = YELLOW_ALT; // striped alternate rows
        v.extreme_bg_color = CREAM; // text edits / scroll bg
        v.override_text_color = Some(INK);
        v.selection.bg_fill = SEL;
        v.selection.stroke = egui::Stroke::new(1.0, INK);
        v.hyperlink_color = COFFEE;
        let r = egui::Rounding::same(5.0);
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.weak_bg_fill = CREAM;
            w.bg_fill = CREAM;
            w.bg_stroke = egui::Stroke::new(1.0, INK);
            w.fg_stroke = egui::Stroke::new(1.6, INK);
            w.rounding = r;
            w.expansion = 0.0;
        }
        cc.egui_ctx.set_style(style);
        let cat = load_cat(&cc.egui_ctx);

        NdrGuiApp {
            cli_path: find_tool("ndr-cli"),
            fuzz_path: find_tool("ndr-fuzz"),
            components: Vec::new(),
            selected: None,
            detected: String::new(),
            filter: String::new(),
            scan_queue: Vec::new(),
            sort: SortKey::Methods,
            sort_desc: true,
            count: 200,
            style: FuzzStyle::Standard,
            out_dir: "loot".into(),
            repros: 0,
            show_settings: false,
            show_about: false,
            scroll_crash: false,
            zoom: 1.0,
            job: None,
            job_kind: JobKind::None,
            json_buf: String::new(),
            log: VecDeque::new(),
            status: "Click \"Scan system\" to find fuzzable RPC/DCOM components.".into(),
            stats: Stats::default(),
            pulse: Pulse::new(),
            cat,
        }
    }

    fn running(&self) -> bool {
        self.job.is_some()
    }

    fn push_log(&mut self, line: impl Into<String>) {
        self.log.push_back(line.into());
        while self.log.len() > 5000 {
            self.log.pop_front();
        }
    }

    fn start(&mut self, kind: JobKind, program: &str, args: Vec<String>) {
        if self.running() {
            return;
        }
        self.json_buf.clear();
        self.job_kind = kind;
        self.push_log(format!("$ {} {}", short(program), args.join(" ")));
        match runner::spawn(program, &args) {
            Ok(job) => {
                self.job = Some(job);
                self.status = "Running...".into();
                if kind == JobKind::Fuzz {
                    self.stats = Stats::default();
                }
            }
            Err(e) => {
                self.push_log(format!("!! failed to launch {}: {e}", short(program)));
                self.status = format!("launch failed: {e}");
                self.job_kind = JobKind::None;
            }
        }
    }

    fn drain(&mut self) {
        let mut done: Option<Option<i32>> = None;
        let mut lines: Vec<String> = Vec::new();
        if let Some(job) = &self.job {
            while let Ok(msg) = job.rx.try_recv() {
                match msg {
                    Msg::Line(l) => lines.push(l),
                    Msg::Done(code) => {
                        done = Some(code);
                        break;
                    }
                }
            }
        }
        let is_json = matches!(self.job_kind, JobKind::Sweep | JobKind::ComList);
        for l in lines {
            if is_json {
                self.json_buf.push_str(&l);
                self.json_buf.push('\n');
            }
            if self.job_kind == JobKind::Fuzz {
                self.classify(&l);
            }
            self.push_log(l);
        }
        if let Some(code) = done {
            self.finish(code);
        }
    }

    fn finish(&mut self, code: Option<i32>) {
        let kind = self.job_kind;
        self.job = None;
        self.job_kind = JobKind::None;
        match kind {
            JobKind::Sweep => {
                self.parse_sweep();
                // More locations queued? Scan the next one before finishing.
                if let Some(dir) = self.scan_queue.pop() {
                    self.start_sweep(&dir);
                    return;
                }
                self.status = format!("Done. {} fuzzable component(s).", self.components.len());
            }
            JobKind::ComList => {
                self.parse_comlist();
                self.status = format!("Done. {} fuzzable component(s).", self.components.len());
            }
            JobKind::Fuzz => {
                self.refresh_repros();
                self.status = match code {
                    Some(0) | None => "Done.".into(),
                    Some(c) => format!("Exited with code {c}."),
                };
            }
            JobKind::None => {}
        }
    }

    fn start_sweep(&mut self, dir: &str) {
        let prog = self.cli_path.clone();
        // --min 1: single-interface servers (like VantageRpcServer.dll, which
        // hosts just 8eefa2e8) must not be filtered out. The methods>0 filter
        // in parse_sweep does the "worthwhile" trimming instead.
        let args = vec![
            "sweep".to_string(),
            dir.to_string(),
            "--min".into(),
            "1".into(),
            "--methods".into(),
            "--json".into(),
        ];
        self.start(JobKind::Sweep, &prog, args);
        self.status = format!("Scanning {} ...", dir);
    }

    fn classify(&mut self, l: &str) {
        let low = l.to_ascii_lowercase();
        if is_crash_line(&low) {
            self.stats.crashes += 1;
            self.pulse.beat(1.0);
            self.status = "!!! possible CRASH - check the log / output folder".into();
            return;
        }
        // A non-zero disconnect count means the server went away mid-fuzz -
        // treat that as a probable crash too (so red triggers without coverage).
        if let Some(d) = num_before(&low, "disc") {
            if d > 0 {
                self.stats.crashes += 1;
                self.pulse.beat(1.0);
                self.status = "!!! server disconnected (possible crash)".into();
                return;
            }
        }
        let mut beat = false;
        if let Some(n) = num_before(&low, "response(s)") {
            self.stats.responses += n;
            self.stats.cases += n;
            self.pulse.beat(0.7);
            beat = true;
        }
        if let Some(n) = num_before(&low, "fault(s)") {
            self.stats.faults += n;
            self.stats.cases += n;
            self.pulse.beat(0.5);
            beat = true;
        }
        if !beat && (low.contains("send") || low.contains("opnum") || low.contains("[live]")) {
            self.pulse.beat(0.3);
        }
    }

    fn parse_sweep(&mut self) {
        // Append this location's results to the running list (ScanSystem cleared
        // it once up front; each location adds to it).
        let Ok(v) = serde_json::from_str::<serde_json::Value>(self.json_buf.trim()) else {
            self.push_log("!! could not parse sweep JSON");
            return;
        };
        if let Some(arr) = v.as_array() {
            for h in arr {
                let methods = h["methods"].as_u64().unwrap_or(0);
                // "worthwhile": only components with actually-decoded methods.
                if methods == 0 {
                    continue;
                }
                let path = h["path"].as_str().unwrap_or("").to_string();
                if self.components.iter().any(|c| c.path == path) {
                    continue;
                }
                let name = file_name(&path);
                self.components.push(Component {
                    server: path.clone(),
                    path,
                    name,
                    arch: h["arch"].as_str().unwrap_or("").to_string(),
                    interfaces: h["interfaces"].as_u64().unwrap_or(0),
                    methods,
                    kind: Kind::Rpc,
                });
            }
        }
        self.sort_components();
    }

    /// Parse `com-list --local --json` and append DCOM classes (out-of-process,
    /// safely fuzzable via IDispatch).
    fn parse_comlist(&mut self) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(self.json_buf.trim()) else {
            self.push_log("!! could not parse com-list JSON");
            return;
        };
        if let Some(arr) = v.as_array() {
            for h in arr {
                if !h["dcom"].as_bool().unwrap_or(false) {
                    continue;
                }
                let clsid = h["clsid"].as_str().unwrap_or("").to_string();
                if clsid.is_empty() || self.components.iter().any(|c| c.path == clsid) {
                    continue;
                }
                let nm = h["name"].as_str().filter(|s| !s.is_empty());
                let progid = h["progid"].as_str().filter(|s| !s.is_empty());
                let mut name = nm.or(progid).map(|s| s.to_string()).unwrap_or_else(|| clsid.clone());
                if h["opc"].as_bool().unwrap_or(false) {
                    name.push_str("  (OPC)");
                }
                let server = h["local_server"].as_str().unwrap_or("").to_string();
                self.components.push(Component {
                    path: clsid,
                    name,
                    server,
                    arch: String::new(),
                    interfaces: 0,
                    methods: 0,
                    kind: Kind::Dcom,
                });
            }
        }
        self.sort_components();
    }

    fn sort_components(&mut self) {
        let key = self.sort;
        self.components.sort_by(|a, b| {
            let o = match key {
                SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortKey::Ifaces => a.interfaces.cmp(&b.interfaces),
                SortKey::Methods => a.methods.cmp(&b.methods),
                SortKey::Arch => a.arch.cmp(&b.arch),
            };
            if self.sort_desc {
                o.reverse()
            } else {
                o
            }
        });
    }

    fn refresh_repros(&mut self) {
        self.repros = 0;
        if let Ok(rd) = std::fs::read_dir(&self.out_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("crash_") && n.ends_with(".bin") {
                    self.repros += 1;
                }
            }
        }
    }

    fn selected_component(&self) -> Option<&Component> {
        let s = self.selected.as_ref()?;
        self.components.iter().find(|c| &c.path == s)
    }

    fn fuzz_cmd(&self) -> Option<(String, Vec<String>)> {
        let c = self.selected_component()?;
        // COM/DCOM -> IDispatch fuzzing; RPC -> hail-mary live.
        if c.kind == Kind::Dcom {
            return Some((
                self.fuzz_path.clone(),
                vec![
                    "com-fuzz".into(),
                    c.path.clone(),
                    "--count".into(),
                    self.count.to_string(),
                    "--i-am-authorized".into(),
                ],
            ));
        }
        // Always -v so the log shows the sent bytes; hail-mary --live does the
        // discover -> bind-match -> fuzz -> catch pipeline.
        let mut a: Vec<String> = vec![
            "-v".into(),
            "hail-mary".into(),
            c.path.clone(),
            "--live".into(),
            "--i-am-authorized".into(),
            "--count".into(),
            self.count.to_string(),
            "--out".into(),
            self.out_dir.clone(),
        ];
        match self.style {
            FuzzStyle::Standard => {}
            FuzzStyle::Json => a.push("--json".into()),
            FuzzStyle::Coverage => a.push("--cov".into()),
        }
        Some((self.fuzz_path.clone(), a))
    }

    fn execute(&mut self, act: Action) {
        match act {
            Action::ScanSystem => {
                self.components.clear();
                self.selected = None;
                self.detected.clear();
                self.stats = Stats::default();
                self.log.clear();
                // Fast: the core OS RPC/DCOM surface only.
                self.scan_queue.clear();
                self.start_sweep(r"C:\Windows\System32");
            }
            Action::ScanApps => {
                if self.running() {
                    return;
                }
                // Installed software (third-party agents like Lenovo Vantage).
                // Appends to whatever's already listed. Slower - walks + decodes
                // Program Files, so a few minutes.
                self.scan_queue = vec![r"C:\Program Files (x86)".into()];
                self.start_sweep(r"C:\Program Files");
            }
            Action::ScanCom => {
                if self.running() {
                    return;
                }
                // Enumerate out-of-process (DCOM) COM classes, appended.
                let prog = self.fuzz_path.clone();
                self.start(
                    JobKind::ComList,
                    &prog,
                    vec!["com-list".into(), "--local".into(), "--json".into()],
                );
                self.status = "Enumerating DCOM classes ...".into();
            }
            Action::ScanDir => {
                if self.running() {
                    return;
                }
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    let dir = p.to_string_lossy().to_string();
                    self.components.clear();
                    self.selected = None;
                    self.detected.clear();
                    self.stats = Stats::default();
                    self.log.clear();
                    self.scan_queue.clear();
                    self.start_sweep(&dir);
                }
            }
            Action::Select(path) => {
                self.selected = Some(path);
                // Compute overview + suggested style, then apply (avoids a
                // borrow of `self` across the field writes).
                let info = self.selected_component().map(|c| {
                    let det = if c.kind == Kind::Dcom {
                        format!("DCOM class · IDispatch fuzzing · {}", c.path)
                    } else {
                        format!(
                            "{} · {} interface(s) · {} method(s)  —  {}",
                            c.arch, c.interfaces, c.methods, c.path
                        )
                    };
                    (det, suggest(c).1)
                });
                if let Some((det, st)) = info {
                    self.detected = det;
                    self.style = st;
                }
            }
            Action::Sort(k) => {
                if self.sort == k {
                    self.sort_desc = !self.sort_desc;
                } else {
                    self.sort = k;
                    self.sort_desc = true;
                }
                self.sort_components();
            }
            Action::Fuzz => {
                if let Some((prog, args)) = self.fuzz_cmd() {
                    self.start(JobKind::Fuzz, &prog, args);
                } else {
                    self.status = "Select a component first.".into();
                }
            }
            Action::Stop => {
                if let Some(j) = &self.job {
                    j.kill();
                }
                self.job = None;
                self.job_kind = JobKind::None;
                self.log.clear();
                self.stats = Stats::default();
                self.status = "Stopped.".into();
            }
            Action::ClearLog => self.log.clear(),
            Action::BrowseOut => {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.out_dir = p.to_string_lossy().to_string();
                }
            }
            Action::OpenLoc(path) => {
                // Open Explorer with the file selected. `/select,` must stay
                // unquoted with the path quoted separately, so bypass Rust's
                // automatic argument quoting via raw_arg.
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    let _ = std::process::Command::new("explorer.exe")
                        .raw_arg(format!("/select,\"{path}\""))
                        .spawn();
                }
            }
            Action::PageHeap(enable) => {
                let Some(path) = self.selected.clone() else {
                    self.status = "Select a component first.".into();
                    return;
                };
                // Toggling PageHeap writes HKLM -> needs elevation. Relaunch the
                // pageheap command elevated via a UAC prompt.
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    let off = if enable { "" } else { ",'--off'" };
                    let ps = format!(
                        "Start-Process -FilePath '{}' -Verb RunAs -ArgumentList 'pageheap','{}'{}",
                        self.fuzz_path.replace('\'', "''"),
                        path.replace('\'', "''"),
                        off
                    );
                    let _ = std::process::Command::new("powershell")
                        .args(["-NoProfile", "-Command", &ps])
                        .creation_flags(0x0800_0000)
                        .spawn();
                }
                self.status = if enable {
                    "PageHeap: accept the UAC prompt, then RESTART the target before fuzzing.".into()
                } else {
                    "PageHeap: disabling (accept the UAC prompt).".into()
                };
            }
        }
    }
}

impl eframe::App for NdrGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_zoom_factor(self.zoom);
        self.drain();
        let mut actions: Vec<Action> = Vec::new();
        let running = self.running();

        // ===== toolbar =====
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("☕ NDRaider").color(COFFEE).size(19.0).strong());
                ui.separator();
                if ui
                    .add_enabled(!running, egui::Button::new(RichText::new("🔎 Scan system").strong()))
                    .on_hover_text("Enumerate C:\\Windows\\System32 for fuzzable RPC/DCOM components (~30s)")
                    .clicked()
                {
                    actions.push(Action::ScanSystem);
                }
                if ui
                    .add_enabled(!running, egui::Button::new("📦 Apps"))
                    .on_hover_text("Also scan installed software in Program Files (slower - a few minutes). Appends to the list.")
                    .clicked()
                {
                    actions.push(Action::ScanApps);
                }
                if ui
                    .add_enabled(!running, egui::Button::new("🔷 COM"))
                    .on_hover_text("Enumerate out-of-process (DCOM) COM classes and append them - fuzz via IDispatch")
                    .clicked()
                {
                    actions.push(Action::ScanCom);
                }
                if ui
                    .add_enabled(!running, egui::Button::new("📁 Folder…"))
                    .on_hover_text("Scan a folder you choose (recursively) - point it anywhere")
                    .clicked()
                {
                    actions.push(Action::ScanDir);
                }
                if ui
                    .add_enabled(running, egui::Button::new(RichText::new("■ Stop").color(Color32::from_rgb(150, 20, 20))))
                    .on_hover_text("Stop and clear")
                    .clicked()
                {
                    actions.push(Action::Stop);
                }
                if running {
                    ui.add(egui::Spinner::new());
                }
                ui.separator();
                ui.label("🔎");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("filter by name")
                        .desired_width(150.0),
                );
                if !self.filter.is_empty() && ui.small_button("✕").clicked() {
                    self.filter.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.selectable_label(self.show_settings, "⚙").clicked() {
                        self.show_settings = !self.show_settings;
                    }
                    if ui.selectable_label(self.show_about, "ℹ").on_hover_text("About").clicked() {
                        self.show_about = !self.show_about;
                    }
                });
            });
            if self.show_settings {
                ui.horizontal(|ui| {
                    ui.label("UI size");
                    ui.add(egui::Slider::new(&mut self.zoom, 0.8..=1.8).step_by(0.05).suffix("×"));
                    ui.separator();
                    ui.label("output");
                    ui.add(egui::TextEdit::singleline(&mut self.out_dir).desired_width(200.0));
                    if ui.button("📁").clicked() {
                        actions.push(Action::BrowseOut);
                    }
                });
            }
            ui.add_space(3.0);
        });

        // ===== status bar (very bottom) - darkened gold =====
        egui::TopBottomPanel::bottom("statusbar")
            .exact_height(22.0)
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(96, 70, 22)) // ~60% darker than the panel gold
                    .inner_margin(egui::Margin::symmetric(8.0, 2.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("● Online").color(Color32::from_rgb(90, 215, 130)).small());
                    ui.separator();
                    ui.label(
                        RichText::new(concat!("NDRaider v", env!("CARGO_PKG_VERSION")))
                            .small()
                            .color(Color32::from_rgba_unmultiplied(244, 233, 205, 190)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("powered by Silly Security Inc. & Zero Science Lab")
                                .small()
                                .color(Color32::from_rgba_unmultiplied(244, 233, 205, 150)),
                        );
                    });
                });
            });

        // ===== bottom: fuzz bar + log (with dissolving-pixel pulse) =====
        let log_resp = egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(250.0)
            .show(ctx, |ui| {
                ui.add_space(3.0);
                // overview + fuzz controls for the selected component
                ui.horizontal(|ui| {
                    match self.selected_component() {
                        Some(c) => {
                            ui.label(RichText::new(format!("▸ {}", c.name)).strong());
                        }
                        None => {
                            ui.label(RichText::new("select a component above").color(COFFEE));
                        }
                    }
                    ui.separator();
                    ui.label("style");
                    ui.selectable_value(&mut self.style, FuzzStyle::Standard, "Standard")
                        .on_hover_text("Structure-aware + havoc mutation (default)");
                    ui.selectable_value(&mut self.style, FuzzStyle::Json, "JSON")
                        .on_hover_text("Fuzz JSON inside byte[] buffers (Vantage-style services)");
                    ui.selectable_value(&mut self.style, FuzzStyle::Coverage, "Coverage")
                        .on_hover_text("Attach the coverage debugger (x64; needs matching privilege)");
                    ui.separator();
                    ui.label("cases");
                    ui.add(egui::DragValue::new(&mut self.count).range(1..=1_000_000).speed(5.0));
                    let can = self.selected.is_some() && !running;
                    let btn = egui::Button::new(RichText::new("⚡ FUZZ").color(CREAM).strong())
                        .fill(COFFEE)
                        .min_size(egui::vec2(92.0, 26.0))
                        .rounding(6.0);
                    if ui.add_enabled(can, btn).clicked() {
                        actions.push(Action::Fuzz);
                    }
                    ui.menu_button("🔒 PageHeap", |ui| {
                        ui.label(
                            RichText::new(
                                "Full PageHeap makes heap overflows fault IMMEDIATELY, so silent\n\
                                 corruption becomes a catchable crash. Applies to an EXE target\n\
                                 (for a DLL service, enable it on the host EXE). Needs admin;\n\
                                 RESTART the target after enabling.",
                            )
                            .small(),
                        );
                        ui.separator();
                        if ui.button("Enable for selected (admin)").clicked() {
                            actions.push(Action::PageHeap(true));
                            ui.close_menu();
                        }
                        if ui.button("Disable for selected (admin)").clicked() {
                            actions.push(Action::PageHeap(false));
                            ui.close_menu();
                        }
                    });
                });
                if !self.detected.is_empty() {
                    ui.label(RichText::new(format!("🔎 {}", self.detected)).small().color(COFFEE));
                }
                ui.separator();
                // status row: pulse + stats
                ui.horizontal(|ui| {
                    let (active, label) = match self.job_kind {
                        JobKind::Sweep => (true, "Scanning"),
                        JobKind::ComList => (true, "Enumerating"),
                        JobKind::Fuzz => (true, "Fuzzing"),
                        JobKind::None => (false, "idle"),
                    };
                    self.pulse.draw(ui, active, self.stats.crashes > 0, label, egui::vec2(210.0, 28.0));
                    ui.separator();
                    stat_chip(ui, "cases", self.stats.cases, COFFEE);
                    stat_chip(ui, "resp", self.stats.responses, Color32::from_rgb(20, 100, 40));
                    stat_chip(ui, "fault", self.stats.faults, Color32::from_rgb(130, 80, 10));
                    let cr = ui
                        .add(
                            egui::Label::new(
                                RichText::new(format!("crash {}", self.stats.crashes))
                                    .monospace()
                                    .color(Color32::from_rgb(160, 25, 25)),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_text("Click to jump to the latest crash in the log");
                    if cr.clicked() {
                        self.scroll_crash = true;
                    }
                    ui.separator();
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("clear").clicked() {
                            actions.push(Action::ClearLog);
                        }
                        if self.repros > 0 {
                            ui.label(RichText::new(format!("💾 {} repro", self.repros)).small());
                        }
                    });
                });
                ui.add_space(2.0);
                ui.separator();
                // one-shot: on crash-chip click, jump to the last crash line
                let want_scroll = self.scroll_crash;
                self.scroll_crash = false;
                egui::ScrollArea::vertical()
                    .stick_to_bottom(!want_scroll)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for l in &self.log {
                            let r = ui.label(RichText::new(l).monospace().color(line_color(l)));
                            if want_scroll && is_crash_line(&l.to_ascii_lowercase()) {
                                r.scroll_to_me(Some(egui::Align::Center));
                            }
                        }
                    });
            });

        // ===== center: the components table =====
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Fuzzable components — {}", self.components.len())).color(COFFEE).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(&self.status).small().color(INK));
                });
            });
            ui.separator();

            if self.components.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Press \"Scan system\" to list worthwhile fuzzable components.").color(INK));
            } else {
                let arrow = |k: SortKey, me: &Self| -> &'static str {
                    if me.sort == k {
                        if me.sort_desc { " ▼" } else { " ▲" }
                    } else {
                        ""
                    }
                };
                let fl = self.filter.trim().to_ascii_lowercase();
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    egui::Grid::new("components")
                        .striped(true)
                        .num_columns(6)
                        .min_col_width(46.0)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            if ui.button(RichText::new(format!("Component{}", arrow(SortKey::Name, self))).strong()).clicked() {
                                actions.push(Action::Sort(SortKey::Name));
                            }
                            if ui.button(RichText::new(format!("Ifaces{}", arrow(SortKey::Ifaces, self))).strong()).clicked() {
                                actions.push(Action::Sort(SortKey::Ifaces));
                            }
                            if ui.button(RichText::new(format!("Methods{}", arrow(SortKey::Methods, self))).strong()).clicked() {
                                actions.push(Action::Sort(SortKey::Methods));
                            }
                            if ui.button(RichText::new(format!("Arch{}", arrow(SortKey::Arch, self))).strong()).clicked() {
                                actions.push(Action::Sort(SortKey::Arch));
                            }
                            ui.label(RichText::new("Type").strong());
                            ui.label(RichText::new("Suggested").strong());
                            ui.end_row();

                            for c in &self.components {
                                if !fl.is_empty()
                                    && !c.name.to_ascii_lowercase().contains(&fl)
                                    && !c.server.to_ascii_lowercase().contains(&fl)
                                {
                                    continue;
                                }
                                let sel = self.selected.as_deref() == Some(c.path.as_str());
                                let resp = ui
                                    .selectable_label(sel, RichText::new(&c.name).monospace().color(INK))
                                    .on_hover_text(&c.path);
                                if resp.clicked() {
                                    actions.push(Action::Select(c.path.clone()));
                                }
                                resp.context_menu(|ui| {
                                    if !c.server.is_empty()
                                        && ui.button("📂 Open file location").clicked()
                                    {
                                        actions.push(Action::OpenLoc(c.server.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.button("📋 Copy path/CLSID").clicked() {
                                        ui.ctx().copy_text(c.path.clone());
                                        ui.close_menu();
                                    }
                                    ui.separator();
                                    ui.label(RichText::new(format!("type: {}", type_label(c.kind))).small());
                                    if c.kind == Kind::Rpc {
                                        ui.label(RichText::new(format!("{} interface(s) · {} method(s)", c.interfaces, c.methods)).small());
                                        ui.label(RichText::new(format!("arch: {}", c.arch)).small());
                                    }
                                    ui.label(RichText::new(format!("suggested: {}", suggest(c).0)).small());
                                    if !c.server.is_empty() {
                                        ui.label(RichText::new(&c.server).small().color(COFFEE));
                                    }
                                });
                                let dash = |n: u64| if c.kind == Kind::Rpc { n.to_string() } else { "-".into() };
                                ui.label(RichText::new(dash(c.interfaces)).monospace().color(INK));
                                ui.label(RichText::new(dash(c.methods)).monospace().color(INK));
                                let arch = if c.arch.is_empty() { "-" } else { c.arch.as_str() };
                                ui.label(RichText::new(arch).monospace().color(INK));
                                let tcol = if c.kind == Kind::Dcom {
                                    Color32::from_rgb(40, 70, 120)
                                } else {
                                    Color32::from_rgb(90, 58, 32)
                                };
                                ui.label(RichText::new(type_label(c.kind)).monospace().strong().color(tcol));
                                let (s, _, col) = suggest(c);
                                ui.label(RichText::new(s).monospace().color(col));
                                ui.end_row();
                            }
                        });
                });
            }

        });

        // Cat: anchored to the panel SEAM (top of the bottom panel) via a
        // foreground layer, so its visible bottom sits flush on that line - no
        // central-panel margin gap. Trimmed content, bottom-right.
        let line_y = log_resp.response.rect.top();
        let screen = ctx.screen_rect();
        if screen.height() > 220.0 {
            let area = egui::Rect::from_min_max(
                egui::pos2(screen.left(), line_y - 260.0),
                egui::pos2(screen.right() - 2.0, line_y),
            );
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("cat_corner"),
            ));
            draw_mascot(&painter, area, self.cat.as_ref());
        }

        // ===== About dialog =====
        if self.show_about {
            let mut open = true;
            egui::Window::new("About NDRaider")
                .collapsible(false)
                .resizable(false)
                .default_width(440.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .frame(
                    egui::Frame::window(&ctx.style())
                        .fill(YELLOW)
                        .stroke(egui::Stroke::new(2.0, COFFEE))
                        .inner_margin(egui::Margin::same(18.0)),
                )
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(404.0);
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(concat!("☕ NDRaider v", env!("CARGO_PKG_VERSION")))
                                .color(COFFEE)
                                .size(20.0)
                                .strong(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Check for updates").clicked() {
                                rfd::MessageDialog::new()
                                    .set_title("Check for updates")
                                    .set_description("Odi Check for updates!")
                                    .set_buttons(rfd::MessageButtons::Ok)
                                    .show();
                            }
                        });
                    });
                    ui.label(RichText::new("Codename: Sani").italics().color(COFFEE));
                    ui.add_space(2.0);
                    ui.label("Windows RPC / DCOM / COM fuzzer.");
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Developed by Silly Security Inc, © 2026 -").strong());
                        ui.hyperlink_to("sillysec.com", "https://sillysec.com");
                    });
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(RichText::new("Quick start").color(COFFEE).strong());
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "1. Scan system / 📦 Apps / 🔷 COM / Folder…  to list targets\n\
                             2. Click a target (Type = RPC or DCOM)\n\
                             3. Optional: 🔒 PageHeap → Enable (admin), restart target\n\
                             4. Set cases and press ⚡ FUZZ - watch the pulse (red = crash)",
                        )
                        .small(),
                    );
                });
            self.show_about = open && self.show_about;
        }

        for a in actions {
            self.execute(a);
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(33));
    }
}

// ---------------------------------------------------------------------------

/// Draw the cat bottom-right in `full`, with its visible content sitting flush
/// on `full.bottom()` (using the trimmed UV so transparent padding is ignored).
fn draw_mascot(p: &egui::Painter, full: egui::Rect, cat: Option<&CatTex>) {
    let maxsz = 155.0_f32.min(full.height() - 30.0);
    match cat {
        Some(c) => {
            let (w, h) = if c.aspect >= 1.0 {
                (maxsz, maxsz / c.aspect)
            } else {
                (maxsz * c.aspect, maxsz)
            };
            let rect = egui::Rect::from_min_size(
                egui::pos2(full.right() - w, full.bottom() - h),
                egui::vec2(w, h),
            );
            p.image(c.tex.id(), rect, c.uv, Color32::WHITE);
        }
        None => {
            let rect = egui::Rect::from_min_size(
                egui::pos2(full.right() - maxsz, full.bottom() - maxsz),
                egui::vec2(maxsz, maxsz),
            );
            draw_cat_fallback(p, rect);
        }
    }
}

/// A simple drawn cat, used only if catgui.png isn't present.
fn draw_cat_fallback(p: &egui::Painter, r: egui::Rect) {
    use egui::{pos2, Shape, Stroke};
    let ink = Color32::from_rgb(26, 23, 18);
    let cream = Color32::from_rgb(244, 233, 205);
    let cx = r.center().x;
    let cy = r.center().y + r.height() * 0.05;
    let hr = r.height() * 0.30;
    p.add(Shape::convex_polygon(
        vec![pos2(cx - hr, cy - hr * 0.6), pos2(cx - hr * 0.4, cy - hr * 1.5), pos2(cx - hr * 0.1, cy - hr * 0.6)],
        ink,
        Stroke::NONE,
    ));
    p.add(Shape::convex_polygon(
        vec![pos2(cx + hr, cy - hr * 0.6), pos2(cx + hr * 0.4, cy - hr * 1.5), pos2(cx + hr * 0.1, cy - hr * 0.6)],
        ink,
        Stroke::NONE,
    ));
    p.circle_filled(pos2(cx, cy), hr, ink);
    p.circle_filled(pos2(cx - hr * 0.4, cy - hr * 0.15), hr * 0.18, cream);
    p.circle_filled(pos2(cx + hr * 0.4, cy - hr * 0.15), hr * 0.18, cream);
}

fn stat_chip(ui: &mut egui::Ui, name: &str, val: u64, color: Color32) {
    ui.label(RichText::new(format!("{name} {val}")).monospace().color(color));
    ui.separator();
}

fn is_crash_line(low: &str) -> bool {
    low.contains("access_violation")
        || low.contains("crash caught")
        || low.contains("!!! crash")
        || low.contains("likely crashed")
        || low.contains("stack_buffer_overrun")
        || low.contains("__fastfail")
}

fn line_color(l: &str) -> Color32 {
    let low = l.to_ascii_lowercase();
    if is_crash_line(&low) || low.starts_with("!!") {
        Color32::from_rgb(150, 20, 20)
    } else if low.contains("fault(s)") {
        Color32::from_rgb(120, 70, 10)
    } else if low.contains("response(s)") || low.contains("bind ok") || low.contains("[live]") {
        Color32::from_rgb(20, 95, 35)
    } else if l.starts_with("$ ") {
        COFFEE
    } else {
        INK
    }
}

fn num_before(hay: &str, marker: &str) -> Option<u64> {
    let idx = hay.find(marker)?;
    let pre = hay[..idx].trim_end();
    let digits: String = pre.chars().rev().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.chars().rev().collect::<String>().parse().ok()
}

fn file_name(p: &str) -> String {
    PathBuf::from(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}

fn short(p: &str) -> String {
    file_name(p)
}

fn find_tool(name: &str) -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(format!("{name}.exe"));
            if cand.exists() {
                return cand.to_string_lossy().to_string();
            }
        }
    }
    name.to_string()
}
