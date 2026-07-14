#[allow(dead_code)]
mod common;

use common::{DatabaseSession, format_error, print_usage};
use idax::address::{Address, BAD_ADDRESS};
use idax::error::ErrorCategory;
use idax::{Error, Result, data, database, function, lines, name, path, xref};
use std::collections::{BTreeMap, BTreeSet};

const REJECTED_FUNCTION_NAMES: &[&str] = &[
    "copyright",
    "char",
    "bool",
    "int",
    "unsigned",
    "long",
    "double",
    "float",
    "signed",
    "license",
    "version",
    "cannot",
    "error",
    "invalid",
    "null",
    "warning",
    "general",
    "argument",
    "written",
    "report",
    "failed",
    "assert",
    "object",
    "integer",
    "unknown",
    "localhost",
    "native",
    "memory",
    "system",
    "write",
    "read",
    "open",
    "close",
    "help",
    "exit",
    "test",
    "return",
    "libs",
    "home",
    "ambiguous",
    "internal",
    "request",
    "inserting",
    "deleting",
    "removing",
    "updating",
    "adding",
    "assertion",
    "flags",
    "overflow",
    "enabled",
    "disabled",
    "enable",
    "disable",
    "virtual",
    "client",
    "server",
    "switch",
    "while",
    "offset",
    "abort",
    "panic",
    "static",
    "updated",
    "pointer",
    "reason",
    "month",
    "year",
    "week",
    "hour",
    "minute",
    "second",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "arguments",
    "corrupt",
    "corrupted",
    "default",
    "success",
    "expecting",
    "missing",
    "phrase",
    "unrecognized",
    "undefined",
];

#[derive(Debug, Clone)]
struct Options {
    input: String,
    apply_candidates: bool,
    apply_sources: bool,
    show: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            apply_candidates: false,
            apply_sources: false,
            show: 20,
        }
    }
}

#[derive(Debug, Clone)]
struct SourceAssociation {
    path: String,
    evidence_address: Address,
    function_address: Address,
    function_name: String,
    evidence: String,
}

#[derive(Debug, Clone)]
struct FunctionCandidate {
    function_address: Address,
    current_name: String,
    suggested_name: String,
    evidence: Vec<String>,
    looks_false: bool,
    from_class_hierarchy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClassObject {
    evidence_address: Address,
    tokens: Vec<String>,
    evidence: String,
}

#[derive(Debug, Default)]
struct Analysis {
    sources: Vec<SourceAssociation>,
    candidates: Vec<FunctionCandidate>,
    classes: Vec<ClassObject>,
    languages: BTreeMap<String, usize>,
    string_count: usize,
    source_observations: usize,
    recoverable_failures: usize,
}

#[derive(Debug, Default)]
struct ApplySummary {
    candidate_renames: usize,
    source_renames: usize,
    failures: usize,
}

fn parse_options(args: &[String]) -> Result<Options> {
    if args.len() < 2 {
        return Err(Error::validation("missing binary_file argument"));
    }
    let mut options = Options {
        input: args[1].clone(),
        ..Options::default()
    };
    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                print_usage(
                    &args[0],
                    "<binary_file> [--apply-candidates] [--apply-sources] [--show <count>]",
                );
                std::process::exit(0);
            }
            "--apply-candidates" => options.apply_candidates = true,
            "--apply-sources" => options.apply_sources = true,
            "--show" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--show requires a value"));
                }
                options.show = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --show value"))?;
            }
            unknown => return Err(Error::validation(format!("unknown option: {unknown}"))),
        }
        index += 1;
    }
    Ok(options)
}

fn is_identifier_start(value: u8) -> bool {
    value.is_ascii_alphabetic() || value == b'_'
}

fn is_identifier_continue(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_'
}

fn parse_identifier(bytes: &[u8], mut position: usize) -> Option<usize> {
    if position >= bytes.len() || !is_identifier_start(bytes[position]) {
        return None;
    }
    position += 1;
    while position < bytes.len() && is_identifier_continue(bytes[position]) {
        position += 1;
    }
    Some(position)
}

fn scoped_names(text: &str, require_scope: bool) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut names = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        let Some(mut end) = parse_identifier(bytes, start) else {
            start += 1;
            continue;
        };
        let mut scopes = 0usize;
        loop {
            if end + 2 > bytes.len() || &bytes[end..end + 2] != b"::" {
                break;
            }
            let component_start = end + 2;
            let mut identifier_start = component_start;
            if identifier_start < bytes.len() && bytes[identifier_start] == b'~' {
                identifier_start += 1;
            }
            if identifier_start < bytes.len() && bytes[identifier_start] == b'<' {
                let inner_start = identifier_start + 1;
                let Some(inner_end) = parse_identifier(bytes, inner_start) else {
                    break;
                };
                if inner_end >= bytes.len() || bytes[inner_end] != b'>' {
                    break;
                }
                end = inner_end + 1;
            } else if let Some(component_end) = parse_identifier(bytes, identifier_start) {
                end = component_end;
            } else {
                break;
            }
            scopes += 1;
        }
        if !require_scope || scopes > 0 {
            names.push(text[start..end].to_owned());
        }
        start = end.max(start + 1);
    }
    names
}

fn first_function_name_in(text: &str) -> Option<String> {
    scoped_names(text, false).into_iter().next()
}

fn class_names_in(text: &str) -> Vec<String> {
    scoped_names(text, true)
}

fn is_source_path_character(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'_' | b'/' | b'\\' | b':' | b'-' | b'.' | b'@' | b'+'
        )
}

fn source_path_in(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    const EXTENSIONS: &[&str] = &[
        ".c++", ".cpp", ".cxx", ".hpp", ".cc", ".rs", ".go", ".ml", ".c", ".h", ".m",
    ];
    for end in 1..=bytes.len() {
        for extension in EXTENSIONS {
            if end < extension.len() || &lower[end - extension.len()..end] != *extension {
                continue;
            }
            if end < bytes.len() && !matches!(bytes[end], b':' | b' ') {
                continue;
            }
            let mut start = end - extension.len();
            while start > 0 && is_source_path_character(bytes[start - 1]) {
                start -= 1;
            }
            if start < end && matches!(bytes[start], b'a'..=b'z' | b'_' | b'/' | b'\\') {
                return Some(text[start..end].to_owned());
            }
        }
    }
    None
}

fn seems_function_name(candidate: &str) -> bool {
    candidate.len() >= 6
        && !REJECTED_FUNCTION_NAMES.contains(&candidate.to_ascii_lowercase().as_str())
        && candidate.bytes().any(|value| value.is_ascii_lowercase())
}

fn looks_false(current_name: &str, candidate: &str) -> bool {
    let current = current_name.to_ascii_lowercase();
    let candidate = candidate.to_ascii_lowercase();
    !current.starts_with("sub_") && !current.contains(&candidate) && !candidate.contains(&current)
}

fn split_scope(name: &str) -> Vec<String> {
    name.split("::")
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn current_function_name(address: Address) -> String {
    name::demangled(address, name::DemangleForm::Short)
        .or_else(|_| name::get(address))
        .unwrap_or_default()
}

fn language_for_path(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
    match extension.as_str() {
        // Preserve the original LANGS insertion order: its broad category is
        // tested before the narrower C and C++ categories.
        "c" | "cc" | "cxx" | "cpp" | "h" | "hpp" => Some("C/C++"),
        "c++" => Some("C++"),
        "m" => Some("Obj-C"),
        "rs" => Some("Rust"),
        "go" => Some("Golang"),
        "ml" => Some("OCaml"),
        _ => None,
    }
}

fn count_source_observation(analysis: &mut Analysis, source_path: &str) {
    if let Some(language) = language_for_path(source_path) {
        *analysis.languages.entry(language.to_owned()).or_default() += 1;
    }
    analysis.source_observations += 1;
}

fn add_source_association(
    analysis: &mut Analysis,
    source_path: String,
    evidence_address: Address,
    function_address: Address,
    evidence: String,
) {
    analysis.sources.push(SourceAssociation {
        path: source_path,
        evidence_address,
        function_address,
        function_name: if function_address == BAD_ADDRESS {
            String::new()
        } else {
            current_function_name(function_address)
        },
        evidence,
    });
}

fn record_function_candidate(
    analysis: &mut Analysis,
    evidence_address: Address,
    evidence: &str,
    rarity: &mut BTreeMap<String, BTreeSet<Address>>,
    function_names: &mut BTreeMap<Address, BTreeSet<String>>,
    raw_function_strings: &mut BTreeMap<Address, BTreeSet<String>>,
) {
    let Some(candidate) = first_function_name_in(evidence) else {
        return;
    };
    if !seems_function_name(&candidate) {
        return;
    }
    match xref::data_refs_to(evidence_address) {
        Ok(references) => {
            for reference in references {
                let Ok(containing) = function::at(reference) else {
                    continue;
                };
                let function_address = containing.start();
                rarity
                    .entry(candidate.clone())
                    .or_default()
                    .insert(function_address);
                function_names
                    .entry(function_address)
                    .or_default()
                    .insert(candidate.clone());
                raw_function_strings
                    .entry(function_address)
                    .or_default()
                    .insert(evidence.to_owned());
            }
        }
        Err(_) => analysis.recoverable_failures += 1,
    }
}

fn add_class_objects(classes: &mut BTreeSet<ClassObject>, address: Address, evidence: &str) {
    for class_name in class_names_in(evidence) {
        let tokens = split_scope(&class_name);
        if tokens.len() >= 2 {
            classes.insert(ClassObject {
                evidence_address: address,
                tokens,
                evidence: evidence.to_owned(),
            });
        }
    }
}

struct StringOptionsRestore(Option<data::StringListOptions>);

impl Drop for StringOptionsRestore {
    fn drop(&mut self) {
        if let Some(options) = self.0.as_ref() {
            let _ = data::configure_string_list(options);
        }
    }
}

fn analyze() -> Result<Analysis> {
    let original = data::string_list_options()?;
    let _restore = StringOptionsRestore(Some(original));
    data::configure_string_list(&data::StringListOptions {
        string_types: vec![0, 1],
        minimum_length: 5,
        only_7bit: true,
        ignore_instructions: false,
        display_only_existing_strings: false,
    })?;
    let literals = data::string_literals(false)?;

    let mut analysis = Analysis {
        string_count: literals.len(),
        ..Analysis::default()
    };
    let mut rarity: BTreeMap<String, BTreeSet<Address>> = BTreeMap::new();
    let mut function_names: BTreeMap<Address, BTreeSet<String>> = BTreeMap::new();
    let mut raw_function_strings: BTreeMap<Address, BTreeSet<String>> = BTreeMap::new();
    let mut classes = BTreeSet::new();

    for literal in &literals {
        if let Some(source_path) = source_path_in(&literal.text) {
            match xref::data_refs_to(literal.address) {
                Ok(references) => {
                    if !references.is_empty() {
                        count_source_observation(&mut analysis, &source_path);
                    }
                    for reference in references {
                        let function_address = function::at(reference)
                            .map(|value| value.start())
                            .unwrap_or(BAD_ADDRESS);
                        add_source_association(
                            &mut analysis,
                            source_path.clone(),
                            reference,
                            function_address,
                            literal.text.clone(),
                        );
                    }
                }
                Err(_) => analysis.recoverable_failures += 1,
            }
        }

        add_class_objects(&mut classes, literal.address, &literal.text);
        record_function_candidate(
            &mut analysis,
            literal.address,
            &literal.text,
            &mut rarity,
            &mut function_names,
            &mut raw_function_strings,
        );
    }

    match name::all(&name::ListOptions::default()) {
        Ok(entries) => {
            for entry in entries {
                if function::at(entry.address).is_err() {
                    continue;
                }
                let class_source = if entry.name.contains("::") {
                    entry.name
                } else {
                    name::demangled(entry.address, name::DemangleForm::Short).unwrap_or(entry.name)
                };
                add_class_objects(&mut classes, entry.address, &class_source);
                record_function_candidate(
                    &mut analysis,
                    entry.address,
                    &class_source,
                    &mut rarity,
                    &mut function_names,
                    &mut raw_function_strings,
                );
            }
        }
        Err(_) => analysis.recoverable_failures += 1,
    }

    for current in function::all() {
        let addresses = match function::code_addresses(current.start()) {
            Ok(value) => value,
            Err(_) => {
                analysis.recoverable_failures += 1;
                continue;
            }
        };
        for address in addresses {
            match lines::source_file_at(address) {
                Ok(source) => {
                    count_source_observation(&mut analysis, &source.filename);
                    add_source_association(
                        &mut analysis,
                        source.filename.clone(),
                        address,
                        current.start(),
                        format!("Debug metadata: {}", source.filename),
                    );
                }
                Err(error) if error.category == ErrorCategory::NotFound => {}
                Err(_) => analysis.recoverable_failures += 1,
            }
        }
    }

    for (function_address, names_for_function) in &function_names {
        let unique: Vec<&String> = names_for_function
            .iter()
            .filter(|candidate| {
                rarity
                    .get(*candidate)
                    .is_some_and(|values| values.len() == 1)
            })
            .collect();
        if unique.len() != 1 {
            continue;
        }
        let suggested_name = unique[0].clone();
        let current_name = current_function_name(*function_address);
        analysis.candidates.push(FunctionCandidate {
            function_address: *function_address,
            current_name: current_name.clone(),
            suggested_name: suggested_name.clone(),
            evidence: raw_function_strings
                .get(function_address)
                .map(|values| values.iter().cloned().collect())
                .unwrap_or_default(),
            looks_false: looks_false(&current_name, &suggested_name),
            from_class_hierarchy: false,
        });
    }

    let mut class_candidate_functions = BTreeSet::new();
    for object in &classes {
        let references = xref::data_refs_to(object.evidence_address).unwrap_or_default();
        let referenced_functions: BTreeSet<Address> = references
            .into_iter()
            .filter_map(|address| function::at(address).ok().map(|value| value.start()))
            .collect();
        if referenced_functions.len() != 1 {
            continue;
        }
        let function_address = *referenced_functions.iter().next().unwrap();
        if !class_candidate_functions.insert(function_address) {
            continue;
        }
        let suggested_name = object.tokens.join("::");
        let current_name = current_function_name(function_address);
        analysis.candidates.push(FunctionCandidate {
            function_address,
            current_name: current_name.clone(),
            suggested_name: suggested_name.clone(),
            evidence: vec![object.evidence.clone()],
            looks_false: looks_false(&current_name, &suggested_name),
            from_class_hierarchy: true,
        });
    }

    analysis.classes = classes.into_iter().collect();
    analysis.sources.sort_by(|left, right| {
        (&left.path, left.function_address, left.evidence_address).cmp(&(
            &right.path,
            right.function_address,
            right.evidence_address,
        ))
    });
    analysis.candidates.sort_by(|left, right| {
        (
            left.looks_false,
            left.function_address,
            &left.suggested_name,
        )
            .cmp(&(
                right.looks_false,
                right.function_address,
                &right.suggested_name,
            ))
    });
    Ok(analysis)
}

fn normalized_candidate(candidate: &str) -> Result<String> {
    name::sanitize_identifier(&candidate.replace("::", "_"))
}

fn source_function_name(source: &SourceAssociation) -> Result<String> {
    let basename = path::basename(&source.path)?;
    let stem = basename
        .rsplit_once('.')
        .map(|(value, _)| value)
        .unwrap_or(&basename);
    name::sanitize_identifier(&format!("{stem}_{:08x}", source.evidence_address))
}

fn apply(options: &Options, analysis: &Analysis) -> ApplySummary {
    let mut summary = ApplySummary::default();
    let mut processed = BTreeSet::new();
    if options.apply_candidates {
        for candidate in &analysis.candidates {
            if !candidate.current_name.starts_with("sub_")
                || !processed.insert(candidate.function_address)
            {
                continue;
            }
            match normalized_candidate(&candidate.suggested_name)
                .and_then(|value| name::set(candidate.function_address, &value))
            {
                Ok(()) => summary.candidate_renames += 1,
                Err(_) => summary.failures += 1,
            }
        }
    }
    if options.apply_sources {
        let mut sources = BTreeMap::new();
        for source in &analysis.sources {
            if source.function_address != BAD_ADDRESS
                && source.function_name.starts_with("sub_")
                && !processed.contains(&source.function_address)
            {
                sources.entry(source.function_address).or_insert(source);
            }
        }
        for (address, source) in sources {
            processed.insert(address);
            match source_function_name(source).and_then(|value| name::set(address, &value)) {
                Ok(()) => summary.source_renames += 1,
                Err(_) => summary.failures += 1,
            }
        }
    }
    summary
}

fn print_report(options: &Options, analysis: &Analysis, applied: &ApplySummary) {
    println!("Magic Strings port (Rust adaptation)");
    println!("input: {}", options.input);
    println!(
        "mode: {}",
        if options.apply_candidates || options.apply_sources {
            "apply"
        } else {
            "report"
        }
    );
    println!("strings: {}", analysis.string_count);
    println!("source_associations: {}", analysis.sources.len());
    println!("function_candidates: {}", analysis.candidates.len());
    println!("class_objects: {}", analysis.classes.len());
    println!("recoverable_failures: {}", analysis.recoverable_failures);
    for (language, count) in &analysis.languages {
        let percent = if analysis.source_observations == 0 {
            0.0
        } else {
            100.0 * *count as f64 / analysis.source_observations as f64
        };
        println!("language_{language}: {count} ({percent:.1}%)");
    }
    println!("candidate_renames: {}", applied.candidate_renames);
    println!("source_renames: {}", applied.source_renames);
    println!("mutation_failures: {}", applied.failures);

    println!(
        "sources_shown: {}",
        analysis.sources.len().min(options.show)
    );
    for source in analysis.sources.iter().take(options.show) {
        println!(
            "  0x{:x} function=0x{:x} {} {} evidence={}",
            source.evidence_address,
            source.function_address,
            source.function_name,
            source.path,
            source.evidence
        );
    }
    println!(
        "candidates_shown: {}",
        analysis.candidates.len().min(options.show)
    );
    for candidate in analysis.candidates.iter().take(options.show) {
        println!(
            "  0x{:x} {} -> {} fp={} origin={} evidence={}",
            candidate.function_address,
            candidate.current_name,
            candidate.suggested_name,
            candidate.looks_false as u8,
            if candidate.from_class_hierarchy {
                "class"
            } else {
                "string"
            },
            candidate.evidence.join(" | ")
        );
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;
    let _session = DatabaseSession::open(&options.input, true)?;
    let analysis = analyze()?;
    let applied = apply(&options, &analysis);
    if options.apply_candidates || options.apply_sources {
        database::save()?;
    }
    print_report(&options, &analysis, &applied);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_original_source_file_extensions_and_boundaries() {
        assert_eq!(
            source_path_in("fatal at src/net/transport.cpp:42"),
            Some("src/net/transport.cpp".to_owned())
        );
        assert_eq!(
            source_path_in(r"C:\work\engine.rs panic"),
            Some(r"C:\work\engine.rs".to_owned())
        );
        assert_eq!(source_path_in("archive.cpp.bak"), None);
        assert_eq!(language_for_path("module.c"), Some("C/C++"));
        assert_eq!(language_for_path("module.cpp"), Some("C/C++"));
        assert_eq!(language_for_path("module.c++"), Some("C++"));
    }

    #[test]
    fn extracts_scoped_candidates_and_class_hierarchies() {
        assert_eq!(
            first_function_name_in("Parser::decode failed"),
            Some("Parser::decode".to_owned())
        );
        assert_eq!(
            class_names_in("ns::Parser::decode()"),
            vec!["ns::Parser::decode".to_owned()]
        );
        assert_eq!(split_scope("ns::Parser::decode").len(), 3);
    }

    #[test]
    fn preserves_original_candidate_filters() {
        assert!(seems_function_name("decodePacket"));
        assert!(!seems_function_name("ERROR"));
        assert!(!seems_function_name("invalid"));
        assert!(!seems_function_name("short"));
        assert!(!looks_false("sub_401000", "decodePacket"));
        assert!(looks_false("parse_header", "decodePacket"));
    }
}
