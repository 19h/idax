mod common;

use common::{format_error, print_usage, write_output};
use idax::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FieldKind {
    CheckBox,
    RadioButton,
    Number,
    Address,
    Choice,
    Raw,
}

impl FieldKind {
    fn as_str(self) -> &'static str {
        match self {
            FieldKind::CheckBox => "checkbox",
            FieldKind::RadioButton => "radio",
            FieldKind::Number => "number",
            FieldKind::Address => "address",
            FieldKind::Choice => "choice",
            FieldKind::Raw => "raw",
        }
    }
}

#[derive(Debug, Clone)]
struct Field {
    line_number: usize,
    group: Option<String>,
    label: String,
    kind: FieldKind,
    choices: Vec<String>,
}

#[derive(Debug, Clone)]
struct Options {
    file: Option<String>,
    inline: Option<String>,
    sample: bool,
    output: Option<String>,
    ask_form_test: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            file: None,
            inline: None,
            sample: true,
            output: None,
            ask_form_test: false,
        }
    }
}

fn parse_options(args: &[String]) -> Result<Options> {
    let mut options = Options::default();
    let mut index = 1usize;

    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                print_usage(
                    &args[0],
                    "[--sample] [--file <form_path>] [--inline <form_text>] [--output <path>] [--ask-form-test]",
                );
                std::process::exit(0);
            }
            "--sample" => {
                options.sample = true;
            }
            "--file" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--file requires a path"));
                }
                options.file = Some(args[index].clone());
                options.sample = false;
            }
            "--inline" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--inline requires form text"));
                }
                options.inline = Some(args[index].clone());
                options.sample = false;
            }
            "--output" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--output requires a path"));
                }
                options.output = Some(args[index].clone());
            }
            "--ask-form-test" => {
                options.ask_form_test = true;
            }
            unknown => {
                return Err(Error::validation(format!("unknown option: {unknown}")));
            }
        }
        index += 1;
    }

    if options.file.is_some() && options.inline.is_some() {
        return Err(Error::validation("use either --file or --inline, not both"));
    }

    Ok(options)
}

fn sample_form() -> &'static str {
    "<##Options##>\n\
<~O~pen brace left alone:C>\n\
<~C~losing brace left alone:C>\n\
<~E~nable pretty output:C>>\n\
\n\
<##Analysis Settings##>\n\
<Block size:D:10:10::>\n\
<Start address:N::18::>\n\
\n\
<##Output Format##>\n\
<Format:b:0:Hex:Decimal:Binary::>\n"
}

fn read_form(options: &Options) -> Result<(String, &'static str)> {
    if let Some(inline) = &options.inline {
        return Ok((inline.clone(), "inline"));
    }
    if let Some(path) = &options.file {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::internal(format!("failed reading '{path}': {err}")))?;
        return Ok((text, "file"));
    }
    Ok((sample_form().to_string(), "sample"))
}

fn strip_hotkeys(text: &str) -> String {
    text.chars().filter(|ch| *ch != '~').collect::<String>()
}

fn parse_group_header(line: &str) -> Option<String> {
    if !line.starts_with("<##") {
        return None;
    }
    let end = line.find("##>")?;
    let name = &line[3..end];
    let trimmed = name.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_line(line: &str, line_number: usize, group: Option<String>) -> Option<Field> {
    if line.starts_with('<') && line.ends_with(":C>") {
        let marker = line.rfind(":C>")?;
        let label = strip_hotkeys(&line[1..marker]).trim().to_string();
        return Some(Field {
            line_number,
            group,
            label,
            kind: FieldKind::CheckBox,
            choices: Vec::new(),
        });
    }

    if line.starts_with('<') && line.ends_with(":R>") {
        let marker = line.rfind(":R>")?;
        let label = strip_hotkeys(&line[1..marker]).trim().to_string();
        return Some(Field {
            line_number,
            group,
            label,
            kind: FieldKind::RadioButton,
            choices: Vec::new(),
        });
    }

    if line.starts_with('<') && (line.contains(":D:") || line.contains(":N:")) {
        let label_end = line.find(':')?;
        let label = strip_hotkeys(&line[1..label_end]).trim().to_string();
        let kind = if line.contains(":D:") {
            FieldKind::Number
        } else {
            FieldKind::Address
        };
        return Some(Field {
            line_number,
            group,
            label,
            kind,
            choices: Vec::new(),
        });
    }

    if line.starts_with('<') && line.contains(":b:") {
        let trimmed = line.trim_start_matches('<').trim_end_matches('>');
        let parts = trimmed.split(':').collect::<Vec<_>>();
        if parts.len() >= 4 {
            let label = strip_hotkeys(parts[0]).trim().to_string();
            let choices = parts[3..]
                .iter()
                .filter(|part| !part.is_empty())
                .map(|part| (*part).to_string())
                .collect::<Vec<_>>();
            return Some(Field {
                line_number,
                group,
                label,
                kind: FieldKind::Choice,
                choices,
            });
        }
    }

    let cleaned = line
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string();
    if cleaned.is_empty() {
        None
    } else {
        Some(Field {
            line_number,
            group,
            label: cleaned,
            kind: FieldKind::Raw,
            choices: Vec::new(),
        })
    }
}

fn parse_form(text: &str) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut current_group: Option<String> = None;

    for (idx, raw_line) in text.lines().enumerate() {
        let mut line = raw_line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        if let Some(group_name) = parse_group_header(&line) {
            current_group = Some(group_name);
            continue;
        }

        if line == ">>" {
            current_group = None;
            continue;
        }

        let mut group_for_line = current_group.clone();
        if line.ends_with(">>") {
            current_group = None;
            group_for_line = None;
            line.pop();
        }

        if let Some(field) = parse_line(&line, idx + 1, group_for_line) {
            fields.push(field);
        }
    }

    fields
}

fn render_report(fields: &[Field], source_kind: &str, ask_form_test: bool) -> String {
    let mut report = String::new();
    report.push_str("qtform_renderer_plugin (Rust adaptation)\n");
    report.push_str(&format!("source: {source_kind}\n"));
    report.push_str(&format!("controls: {}\n", fields.len()));
    report.push_str("\n");

    report.push_str(&format!(
        "{:<5} {:<12} {:<18} {:<30} Detail\n",
        "Line", "Kind", "Group", "Label"
    ));
    report.push_str(
        "------------------------------------------------------------------------------------------\n",
    );
    for field in fields {
        let group = field.group.as_deref().unwrap_or("<none>");
        let detail = if field.choices.is_empty() {
            String::new()
        } else {
            field.choices.join(" | ")
        };
        report.push_str(&format!(
            "{:<5} {:<12} {:<18} {:<30} {}\n",
            field.line_number,
            field.kind.as_str(),
            group,
            field.label,
            detail
        ));
    }

    let mut counts: BTreeMap<FieldKind, usize> = BTreeMap::new();
    for field in fields {
        *counts.entry(field.kind).or_insert(0) += 1;
    }

    report.push_str("\nCounts by kind\n");
    report.push_str("--------------\n");
    for (kind, count) in counts {
        report.push_str(&format!("{}: {}\n", kind.as_str(), count));
    }

    report.push_str("\nask_form bridge\n");
    report.push_str("---------------\n");
    if ask_form_test {
        report.push_str(
            "requested: yes\nstatus: not-executed (idax currently does not expose a public ui::ask_form wrapper)\n",
        );
    } else {
        report.push_str(
            "requested: no\nstatus: not-executed (idax currently does not expose a public ui::ask_form wrapper)\n",
        );
    }

    report
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;
    let (form_text, source_kind) = read_form(&options)?;

    let fields = parse_form(&form_text);
    let report = render_report(&fields, source_kind, options.ask_form_test);
    write_output(options.output.as_deref(), &report)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
