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
        "redox-smoke" => redox_smoke(),
        "redox-test" => {
            println!("Redox QEMU smoke test is not implemented yet. Use `cargo xtask redox-smoke` for the P1 scaffold.");
            Ok(())
        }
        _ => {
            println!("Usage: cargo xtask <task>");
            println!("Tasks:");
            println!("  build-examples  Build example capsules");
            println!("  test            Run fmt, clippy, and workspace tests");
            println!("  redox-smoke     Prepare P1 Redox smoke-test artifacts");
            println!("  redox-test      Run Redox QEMU smoke test (P1)");
            Ok(())
        }
    }
}

fn redox_smoke() -> anyhow::Result<()> {
    let capsule = "target/redox-smoke/hello-service.cocoon";
    let overlay_dir = std::path::Path::new("target/redox-smoke/overlay/capsules");
    std::fs::create_dir_all(overlay_dir)?;

    run(
        "cargo",
        &[
            "run",
            "-p",
            "cocoon-cli",
            "--",
            "build",
            "examples/hello-service",
            "--output",
            capsule,
        ],
    )?;
    println!("PASS build hello-service.cocoon");

    run(
        "cargo",
        &["run", "-p", "cocoon-cli", "--", "verify", capsule],
    )?;
    println!("PASS verify capsule");

    run("cargo", &["run", "-p", "cocoon-cli", "--", "plan", capsule])?;
    println!("PASS generate runtime plan");

    std::fs::copy(capsule, overlay_dir.join("hello-service.cocoon"))?;
    println!("PASS image overlay prepared");
    Ok(())
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: {program} {}", args.join(" "));
    }
    Ok(())
}
