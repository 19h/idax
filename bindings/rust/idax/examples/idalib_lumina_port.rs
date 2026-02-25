mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::address::BAD_ADDRESS;
use idax::{function, lumina, name, Result};

fn resolve_target_function() -> Result<u64> {
    if let Ok(main) = name::resolve("main", BAD_ADDRESS) {
        return Ok(main);
    }
    Ok(function::by_index(0)?.start())
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<binary_file>");
        return Err(idax::Error::validation("missing binary_file argument"));
    }

    let _session = DatabaseSession::open(&args[1], true)?;
    let target = resolve_target_function()?;

    let pull = lumina::pull(&[target], true, lumina::Feature::PrimaryMetadata)?;
    let push = lumina::push(
        &[target],
        lumina::PushMode::PreferBetterOrDifferent,
        lumina::Feature::PrimaryMetadata,
    )?;

    println!(
        "target={:#x}\npull: requested={} completed={} succeeded={} failed={}",
        target, pull.requested, pull.completed, pull.succeeded, pull.failed
    );
    println!(
        "push: requested={} completed={} succeeded={} failed={}",
        push.requested, push.completed, push.succeeded, push.failed
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", format_error(&err));
        std::process::exit(1);
    }
}
