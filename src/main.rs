fn main() {
    if let Err(e) = wasm_trim::cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
