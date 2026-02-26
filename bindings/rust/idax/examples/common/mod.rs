use idax::address::{Address, BAD_ADDRESS};
use idax::error::Result;
use idax::{analysis, database, name, Error};

pub struct DatabaseSession {
    open: bool,
}

impl DatabaseSession {
    pub fn open(input_path: &str, analyze_input: bool) -> Result<Self> {
        database::init()?;
        database::open(input_path, analyze_input)?;
        if analyze_input {
            if let Err(error) = analysis::wait() {
                if cfg!(target_os = "windows") {
                    eprintln!(
                        "warning: analysis::wait failed on Windows CI, continuing: {}",
                        format_error(&error)
                    );
                } else {
                    return Err(error);
                }
            }
        }
        Ok(Self { open: true })
    }
}

impl Drop for DatabaseSession {
    fn drop(&mut self) {
        if self.open {
            let _ = database::close(false);
            self.open = false;
        }
    }
}

pub fn format_error(error: &idax::Error) -> String {
    if error.context.is_empty() {
        format!("[{:?}:{}] {}", error.category, error.code, error.message)
    } else {
        format!(
            "[{:?}:{}] {} ({})",
            error.category, error.code, error.message, error.context
        )
    }
}

pub fn print_usage(binary: &str, usage: &str) {
    eprintln!("Usage: {binary} {usage}");
}

pub fn parse_address(token: &str) -> Result<Address> {
    let trimmed = token.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .map_err(|_| Error::validation(format!("invalid hex address: {token}")));
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| Error::validation(format!("invalid address: {token}")))
}

pub fn resolve_symbol_or_address(token: &str) -> Result<Address> {
    if let Ok(address) = parse_address(token) {
        return Ok(address);
    }
    name::resolve(token, BAD_ADDRESS)
}

pub fn write_output(path: Option<&str>, content: &str) -> Result<()> {
    if let Some(output_path) = path {
        std::fs::write(output_path, content).map_err(|err| {
            Error::internal(format!("failed writing output file '{output_path}': {err}"))
        })?;
    } else {
        print!("{content}");
    }
    Ok(())
}
