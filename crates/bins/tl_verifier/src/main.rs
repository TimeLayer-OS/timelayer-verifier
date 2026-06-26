use std::env;
use std::fs;
use std::path::Path;

use tl_receipts::ReceiptStatus;
use tl_verify_public::{verify_bytes, PublicVerdict};

const MAX_CERT_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;

fn usage() -> i32 {
    eprintln!(
        "timelayer-verifier {}\n\
         \n\
         Offline verifier for TimeLayer receipts. No network, no roster lookup:\n\
         a receipt is a self-contained pair of files and verifies on its own.\n\
         \n\
         USAGE:\n    \
             timelayer-verifier verify <cert.tlcert> <bundle.tlbundle>\n    \
             timelayer-verifier --version\n\
         \n\
         OUTPUT:\n    \
             VALID FINAL     the receipt is authentic and complete (exit 0)\n    \
             UNVERIFIABLE    the pair does not verify (exit 1)",
        env!("CARGO_PKG_VERSION")
    );
    1
}

fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("verify") if args.len() == 4 => {
            verify_files(Path::new(&args[2]), Path::new(&args[3]))
        }
        Some("--version") | Some("-V") => {
            println!("timelayer-verifier {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => usage(),
    }
}

fn read_or_report(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    match read_limited(path, max_bytes) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            eprintln!("{}", error);
            None
        }
    }
}

fn verify_files(cert_path: &Path, bundle_path: &Path) -> i32 {
    let Some(cert) = read_or_report(cert_path, MAX_CERT_BYTES) else {
        return 1;
    };
    let Some(bundle) = read_or_report(bundle_path, MAX_BUNDLE_BYTES) else {
        return 1;
    };
    match verify_bytes(&cert, Some(&bundle)) {
        PublicVerdict::VALID(ReceiptStatus::FINAL) => {
            println!("VALID FINAL");
            0
        }
        _ => {
            println!("UNVERIFIABLE");
            1
        }
    }
}

fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{} exceeds maximum size {} bytes",
            path.display(),
            max_bytes
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{} exceeds maximum size {} bytes",
            path.display(),
            max_bytes
        ));
    }
    Ok(bytes)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    std::process::exit(run(&args));
}
