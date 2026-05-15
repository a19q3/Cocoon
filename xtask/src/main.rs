#![forbid(unsafe_code)]

use std::process::Command;

const REDOX_TARGET: &str = "x86_64-unknown-redox";

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

    run("cargo", &["build", "-p", "cocoon-cli"])?;
    println!("PASS host build cocoon");

    if run_optional(
        "cargo",
        &["check", "-p", "cocoon-cli", "--target", REDOX_TARGET],
    )? {
        println!("PASS redox target cargo check");
    } else {
        println!("TODO redox target cargo check (install target with `rustup target add {REDOX_TARGET}`)");
    }

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

    println!("TODO redox binary link (requires Redox C sysroot/toolchain, not only rust-std)");
    println!("TODO boot redox qemu");
    println!("TODO run cocoon verify inside redox");
    println!("TODO run cocoon plan inside redox");
    println!("TODO install capsule inside redox");
    println!("TODO run hello-service inside redox");
    println!("TODO collect receipts/logs");
    Ok(())
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: {program} {}", args.join(" "));
    }
    Ok(())
}

fn run_optional(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    let status = Command::new(program).args(args).status()?;
    Ok(status.success())
}
