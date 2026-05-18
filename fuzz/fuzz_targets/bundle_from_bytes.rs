#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Any input must not panic; we only exercise the public surface.
    if let Ok(reader) = cocoon_bundle::BundleReader::from_bytes(data) {
        let _ = reader.verify();
        let _ = reader.manifest();
    }
});
