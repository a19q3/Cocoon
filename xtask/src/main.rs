#![forbid(unsafe_code)]

use std::process::Command;

fn main() -> anyhow::Result<()> {
    let task = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "help".to_string());
    match task.as_str() {
        "build-examples" => run(
            "cargo",
            &[
                "run",
                "-p",
                "cocoon-cli",
                "--",
                "build",
                "examples/hello-service",
            ],
        ),
        "test" => {
            run("cargo", &["fmt", "--all", "--check"])?;
            run(
                "cargo",
                &[
                    "clippy",
                    "--all-targets",
                    "--all-features",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            run("cargo", &["test", "--workspace"])?;
            Ok(())
        }
        "redox-test" => {
            println!("Redox QEMU smoke test — not yet implemented.");
            Ok(())
        }
        _ => {
            println!("Usage: cargo xtask <task>");
            println!("Tasks:");
            println!("  build-examples  Build example capsules");
            println!("  test            Run fmt, clippy, and workspace tests");
            println!("  redox-test      Run Redox QEMU smoke test (P1)");
            Ok(())
        }
    }
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: {program} {}", args.join(" "));
    }
    Ok(())
}
