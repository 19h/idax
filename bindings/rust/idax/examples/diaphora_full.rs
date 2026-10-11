//! Shared complete Diaphora application launcher.
//! Usage: diaphora_full <python> <application-root> <application arguments...>
use std::process::Command;

fn main() {
    let mut arguments = std::env::args().skip(1);
    let Some(python) = arguments.next() else {
        eprintln!("usage: diaphora_full <python> <application-root> <arguments...>");
        std::process::exit(2);
    };
    let Some(root) = arguments.next() else {
        eprintln!("application root is required");
        std::process::exit(2);
    };
    match Command::new(python).current_dir(root)
        .args(["-m", "examples.diaphora"]).args(arguments).status() {
        Ok(result) => std::process::exit(result.code().unwrap_or(1)),
        Err(error) => {
            eprintln!("cannot launch the shared Diaphora application: {error}");
            std::process::exit(1);
        }
    }
}
