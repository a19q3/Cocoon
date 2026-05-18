#![forbid(unsafe_code)]

use std::process::{Command, Stdio};

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
        "host-smoke" => host_smoke(),
        "redox-target-smoke" => redox_target_smoke(),
        "redoxer-smoke" => redoxer_smoke(),
        "qemu-smoke" => {
            qemu_smoke();
            Ok(())
        }
        "redox-test" => {
            println!(
                "Redox QEMU smoke test is not implemented yet. Use `cargo xtask redox-smoke` for the P1 scaffold."
            );
            Ok(())
        }
        _ => {
            println!("Usage: cargo xtask <task>");
            println!("Tasks:");
            println!("  build-examples  Build example capsules");
            println!("  test            Run fmt, clippy, and workspace tests");
            println!("  host-smoke      Run host-side P1 smoke checks");
            println!("  redox-target-smoke");
            println!("                  Check Redox target portability and link readiness");
            println!("  redoxer-smoke  Check Redoxer toolchain build readiness");
            println!("  qemu-smoke      Report QEMU smoke-test readiness");
            println!("  redox-smoke     Prepare P1 Redox smoke-test artifacts");
            println!("  redox-test      Run Redox QEMU smoke test (P1)");
            Ok(())
        }
    }
}

fn redox_smoke() -> anyhow::Result<()> {
    host_smoke()?;
    redox_target_smoke()?;
    qemu_smoke();
    Ok(())
}

fn host_smoke() -> anyhow::Result<()> {
    let capsule = "target/redox-smoke/hello-service.cocoon";
    let overlay_dir = std::path::Path::new("target/redox-smoke/overlay/capsules");
    std::fs::create_dir_all(overlay_dir)?;

    print_section("Host smoke");

    run("cargo", &["build", "-p", "cocoon-cli"])?;
    println!("PASS host build cocoon");

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

fn redox_target_smoke() -> anyhow::Result<()> {
    print_section("Redox target smoke");
    let mut any_todo = false;

    if run_optional(
        "cargo",
        &["check", "-p", "redox-link-probe", "--target", REDOX_TARGET],
    )? {
        println!("PASS redox link probe cargo check");
    } else {
        println!(
            "TODO redox link probe cargo check (install target with `rustup target add {REDOX_TARGET}`)"
        );
        any_todo = true;
    }

    if run_optional(
        "cargo",
        &["check", "-p", "cocoon-cli", "--target", REDOX_TARGET],
    )? {
        println!("PASS cocoon-cli redox cargo check");
    } else {
        println!(
            "TODO cocoon-cli redox cargo check (install target with `rustup target add {REDOX_TARGET}`)"
        );
        any_todo = true;
    }

    if run_optional(
        "cargo",
        &["build", "-p", "redox-link-probe", "--target", REDOX_TARGET],
    )? {
        println!("PASS redox link probe binary link");
    } else {
        println!("TODO redox link probe binary link (requires Redox C sysroot/toolchain)");
        any_todo = true;
    }

    if run_optional(
        "cargo",
        &["build", "-p", "cocoon-cli", "--target", REDOX_TARGET],
    )? {
        println!("PASS cocoon-cli redox binary link");
    } else {
        println!("TODO cocoon-cli redox binary link (requires Redox C sysroot/toolchain)");
        any_todo = true;
    }

    redoxer_smoke()?;

    if any_todo {
        anyhow::bail!("Some Redox target smoke checks were skipped. Install the Redox toolchain to run them.");
    }

    Ok(())
}

fn redoxer_smoke() -> anyhow::Result<()> {
    print_section("Redoxer smoke");

    if !program_available("redoxer")? {
        println!("SKIP redoxer available (install with `cargo install redoxer`)");
        println!("SKIP redoxer build redox-link-probe");
        println!("SKIP redoxer build cocoon-cli");
        println!("SKIP redoxer run cocoon --help");
        return Ok(());
    }

    println!("PASS redoxer available");

    if run_optional("redoxer", &["build", "-p", "redox-link-probe"])? {
        println!("PASS redoxer build redox-link-probe");
    } else {
        println!("TODO redoxer build redox-link-probe");
    }

    if run_optional("redoxer", &["build", "-p", "cocoon-cli"])? {
        println!("PASS redoxer build cocoon-cli");
    } else {
        println!("TODO redoxer build cocoon-cli");
    }

    if run_optional("redoxer", &["run", "-p", "cocoon-cli", "--", "--help"])? {
        println!("PASS redoxer run cocoon --help");
    } else {
        println!("TODO redoxer run cocoon --help");
    }

    Ok(())
}

fn qemu_smoke() {
    print_section("QEMU smoke");

    println!("TODO boot redox qemu");
    println!("TODO run cocoon verify inside redox");
    println!("TODO run cocoon plan inside redox");
    println!("TODO install capsule inside redox");
    println!("TODO run hello-service inside redox");
    println!("TODO collect receipts/logs");
}

fn print_section(name: &str) {
    println!();
    println!("== {name} ==");
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: {program} {}", args.join(" "));
    }
    Ok(())
}

fn run_optional(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    let mut command = Command::new(program);
    command.args(args);

    if std::env::var_os("COCOON_SMOKE_VERBOSE").is_none() {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let status = command.status()?;
    Ok(status.success())
}

fn program_available(program: &str) -> anyhow::Result<bool> {
    let status = Command::new(program)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
