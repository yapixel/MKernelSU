use std::env::args;
use std::io::{copy, stderr, stdin, stdout};
use std::process::{exit, Command, Stdio};
use std::thread;

pub fn cmd_wrapper() -> ! {
    let mut child = Command::new("/system/bin/cmd")
        .args(args().skip(1))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();
    let mut my_stdin = stdin();
    let mut my_stdout = stdout();
    let mut my_stderr = stderr();
    thread::spawn(move || {
        let _ = copy(&mut my_stdin, &mut child_stdin);
    });
    let handle = thread::spawn(move || {
        let _ = copy(&mut child_stderr, &mut my_stderr);
    });
    let _ = copy(&mut child_stdout, &mut my_stdout);
    let _ = handle.join();
    if let Ok(status) = child.wait() {
        if let Some(code) = status.code() {
            exit(code);
        }
    }
    exit(-1);
}
