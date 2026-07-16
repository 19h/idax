#[allow(dead_code)]
#[path = "../examples/diaphora_exact_port.rs"]
mod port;

fn main() {
    if std::env::var_os("IDADIR").is_none()
        || std::env::var_os("IDAX_DIAPHORA_REFERENT_RUNTIME_FIXTURE").is_none()
    {
        println!(
            "test initialized_referent_runtime ... ignored, set IDADIR and IDAX_DIAPHORA_REFERENT_RUNTIME_FIXTURE"
        );
        return;
    }

    println!("running 1 test");
    print!("test initialized_referent_runtime ... ");
    port::tests::initialized_referent_runtime_applies_preserves_reopens_and_rejects_ambiguity();
    println!("ok");
    println!("\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 filtered out");
}
