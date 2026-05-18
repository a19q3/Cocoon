#![forbid(unsafe_code)]

fn main() {
    if std::env::args().any(|arg| arg == "--authority-self-test") {
        if let Err(error) = authority_self_test() {
            eprintln!("SERVICE FAIL authority self-test: {error}");
            std::process::exit(1);
        }
        return;
    }

    println!("Hello from Cocoon hello-service!");
    println!("This binary would run inside a Redox namespace with declared permissions.");
}

fn authority_self_test() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    let profile = parse_optional_string_arg(&args, "--profile")
        .unwrap_or_else(|| "hello-service".to_string());
    let allowed_preopen_fd = parse_usize_arg(&args, "--allowed-preopen-fd")?;
    let denied_file_path = parse_string_arg(&args, "--denied-file-path")?;
    let hidden_scheme_path = parse_string_arg(&args, "--hidden-scheme-path")?;

    let allowed = read_allowed_preopen(allowed_preopen_fd)?;
    if allowed.is_empty() {
        return Err("declared preopen read returned no bytes".to_string());
    }

    println!("PASS fexec installed capsule entrypoint");
    println!("SERVICE PROFILE {profile}");
    println!("PASS service reads declared resource");

    if std::fs::File::open(&denied_file_path).is_ok() {
        return Err(format!(
            "denied ambient path opened unexpectedly: {denied_file_path}"
        ));
    }
    println!("PASS denied ambient path rejected");

    if std::fs::File::open(&hidden_scheme_path).is_ok() {
        return Err(format!(
            "undeclared scheme opened unexpectedly: {hidden_scheme_path}"
        ));
    }
    println!("PASS undeclared tcp scheme rejected");
    Ok(())
}

fn parse_optional_string_arg(args: &[String], name: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == name)?;
    args.get(index + 1).cloned()
}

fn parse_string_arg(args: &[String], name: &str) -> Result<String, String> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Err(format!("missing {name}"));
    };
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn parse_usize_arg(args: &[String], name: &str) -> Result<usize, String> {
    parse_string_arg(args, name)?
        .parse()
        .map_err(|error| format!("invalid {name}: {error}"))
}

#[cfg(target_os = "redox")]
fn read_allowed_preopen(fd: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0_u8; 4096];
    let bytes_read =
        libredox::call::read(fd, &mut buffer).map_err(|error| format!("read fd {fd}: {error}"))?;
    buffer.truncate(bytes_read);
    Ok(buffer)
}

#[cfg(not(target_os = "redox"))]
fn read_allowed_preopen(_fd: usize) -> Result<Vec<u8>, String> {
    Err("authority self-test is Redox-only".to_string())
}
