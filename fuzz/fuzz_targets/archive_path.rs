#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on arbitrary bytes; the function is pure and returns a Result.
    let path = std::path::Path::new(std::str::from_utf8(data).unwrap_or(""));
    let _ = cocoon_bundle::archive_path_to_key(path);
});
