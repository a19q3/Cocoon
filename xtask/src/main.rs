use std::process::Command;

fn main() -> anyhow::Result<()> {
    let task = std::env::args().nth(1).unwrap_or_else(|| "help".to_string());
    match task.as_str() {
        "build-examples" => {
            let status = Command::new("cargo")
                .args(["run", "-p", "cocoon-cli", "--", "build", "examples/hello-service"])
                .status()?;
            if !status.success() {
                anyhow::bail!("build-examples failed");
            }
            Ok(())
        }
        "test" => {
            let status = Command::new("cargo").args(["test", "--workspace"]).status()?;
            if !status.success() {
                anyhow::bail!("tests failed");
            }
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
            println!("  test            Run workspace tests");
            println!("  redox-test      Run Redox QEMU smoke test (P1)");
            Ok(())
        }
    }
}
