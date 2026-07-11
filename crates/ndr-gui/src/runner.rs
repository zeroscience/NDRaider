//! Spawn a child process (ndr-cli / ndr-fuzz) and stream its stdout+stderr back
//! to the UI over a channel, line by line, without blocking the GUI thread.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;

/// A message from a running child.
pub enum Msg {
    /// One line of output (from stdout or stderr).
    Line(String),
    /// The process exited with this status code (if known).
    Done(Option<i32>),
}

/// A handle to a running (or finished) child process.
pub struct Job {
    pub rx: Receiver<Msg>,
    child: Arc<Mutex<Option<Child>>>,
}

impl Job {
    /// Ask the child to stop (best-effort).
    pub fn kill(&self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(c) = guard.as_mut() {
                let _ = c.kill();
            }
        }
    }
}

/// Spawn `program args...`, returning a `Job` that streams its output.
pub fn spawn(program: &str, args: &[String]) -> std::io::Result<Job> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Don't flash a console window for each child (they're console apps spawned
    // from a GUI). CREATE_NO_WINDOW = 0x08000000.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn()?;

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    let (tx, rx) = channel::<Msg>();
    let tx_out = tx.clone();
    let tx_err = tx.clone();
    let tx_done = tx;

    // stderr reader
    let err_handle = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx_err.send(Msg::Line(line)).is_err() {
                break;
            }
        }
    });

    let child = Arc::new(Mutex::new(Some(child)));
    let child_for_thread = child.clone();

    // stdout reader; on EOF, wait for the child and emit Done.
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx_out.send(Msg::Line(line)).is_err() {
                return;
            }
        }
        // stdout closed -> process is finishing. Drain stderr, then reap.
        let _ = err_handle.join();
        let code = {
            let mut guard = child_for_thread.lock().unwrap();
            match guard.take() {
                Some(mut c) => c.wait().ok().and_then(|s| s.code()),
                None => None,
            }
        };
        let _ = tx_done.send(Msg::Done(code));
    });

    Ok(Job { rx, child })
}
