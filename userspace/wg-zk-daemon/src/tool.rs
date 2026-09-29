//! Running the external `wg` and `ip` tools from async code (`tokio::process`, never the
//! blocking `std::process`). Key material is passed on stdin, never on the command line.
//! A tool that does not finish within [`TOOL_TIMEOUT`] is killed.

use anyhow::{anyhow, bail, Context, Result};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub const TOOL_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `program args...`, feeding `stdin` if given. Fails on a non-zero exit status. The
/// error names the program and its first argument only, since later arguments can be keys.
pub async fn run(program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<()> {
    exec(program, args, stdin, false).await.map(drop)
}

/// Like [`run`], and returns what the tool wrote to stdout.
pub async fn output(program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    exec(program, args, stdin, true).await
}

async fn exec(program: &str, args: &[String], stdin: Option<&[u8]>, capture_stdout: bool) -> Result<Vec<u8>> {
    let what = match args.first() {
        Some(a) => format!("{program} {a}"),
        None => program.to_string(),
    };
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(if capture_stdout { Stdio::piped() } else { Stdio::null() })
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().with_context(|| format!("spawn {what}"))?;
    if let Some(data) = stdin {
        let mut pipe = child.stdin.take().ok_or_else(|| anyhow!("{what}: stdin not captured"))?;
        // A tool that exits early closes the pipe; its exit status then tells what happened.
        let _ = pipe.write_all(data).await;
        drop(pipe); // EOF
    }
    let out = timeout(TOOL_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| anyhow!("{what}: no exit within {TOOL_TIMEOUT:?}"))?
        .with_context(|| format!("wait for {what}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{what} failed ({}): {}", out.status, err.trim());
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn stdin_reaches_the_tool() {
        run("sh", &args(&["-c", "read x; [ \"$x\" = secret ]"]), Some(b"secret\n")).await.expect("match");
        assert!(run("sh", &args(&["-c", "read x; [ \"$x\" = secret ]"]), Some(b"other\n")).await.is_err());
    }

    #[tokio::test]
    async fn failure_reports_status_and_stderr_only() {
        let err = run("sh", &args(&["-c", "echo boom >&2; exit 3", "KEYMATERIAL"]), None)
            .await
            .expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("boom") && msg.contains('3'), "{msg}");
        assert!(!msg.contains("KEYMATERIAL"), "later arguments must not be echoed: {msg}");
    }

    #[tokio::test]
    async fn missing_program_is_an_error() {
        assert!(run("wgzk-no-such-program", &[], None).await.is_err());
    }

    #[tokio::test]
    async fn output_returns_stdout() {
        let out = output("sh", &args(&["-c", "echo one; echo two"]), None).await.expect("output");
        assert_eq!(out, b"one\ntwo\n");
        assert!(output("sh", &args(&["-c", "echo partial; exit 1"]), None).await.is_err());
    }
}
