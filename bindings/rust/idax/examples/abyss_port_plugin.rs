mod common;

use common::{format_error, print_usage, resolve_symbol_or_address, write_output, DatabaseSession};
use idax::{decompiler, function, lines, Error, Result};
use std::collections::{BTreeSet, HashSet, VecDeque};

#[derive(Debug, Clone)]
struct Options {
    input: String,
    target: Option<String>,
    max_lines: usize,
    hierarchy_depth: usize,
    item_index: bool,
    show_tags: bool,
    output: Option<String>,
    tokens: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            target: None,
            max_lines: 140,
            hierarchy_depth: 2,
            item_index: false,
            show_tags: false,
            output: None,
            tokens: vec!["return".to_string()],
        }
    }
}

#[derive(Debug, Clone)]
struct HierarchyNode {
    depth: usize,
    address: u64,
    name: String,
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
                    "<binary_file> [--function <name|ea>] [--max-lines <n>] [--hier-depth <n>] [--item-index] [--show-tags] [--token <word>] [--output <path>]",
                );
                std::process::exit(0);
            }
            "--function" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--function requires an argument"));
                }
                options.target = Some(args[index].clone());
            }
            "--max-lines" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--max-lines requires a numeric value"));
                }
                options.max_lines = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --max-lines value"))?;
            }
            "--hier-depth" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--hier-depth requires a numeric value"));
                }
                options.hierarchy_depth = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --hier-depth value"))?;
            }
            "--item-index" => {
                options.item_index = true;
            }
            "--show-tags" => {
                options.show_tags = true;
            }
            "--token" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--token requires a value"));
                }
                options.tokens.push(args[index].clone());
            }
            "--output" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--output requires a file path"));
                }
                options.output = Some(args[index].clone());
            }
            unknown => {
                return Err(Error::validation(format!("unknown option: {unknown}")));
            }
        }
        index += 1;
    }

    if options.tokens.is_empty() {
        options.tokens.push("return".to_string());
    }

    Ok(options)
}

fn containing_function(address: u64) -> Result<function::Function> {
    if let Ok(found) = function::at(address) {
        return Ok(found);
    }

    for candidate in function::all() {
        if address >= candidate.start() && address < candidate.end() {
            return Ok(candidate);
        }
    }

    Err(Error::not_found(format!(
        "no function contains address 0x{address:x}"
    )))
}

fn choose_target_function(options: &Options) -> Result<function::Function> {
    if let Some(target) = &options.target {
        let ea = resolve_symbol_or_address(target)?;
        return containing_function(ea);
    }

    for candidate in function::all() {
        if candidate.is_library() || candidate.is_thunk() {
            continue;
        }
        if candidate.size() < 16 {
            continue;
        }
        return Ok(candidate);
    }

    function::by_index(0)
}

fn apply_token_colorizer(
    lines_in: &mut [String],
    body_start_line: usize,
    tokens: &[String],
) -> usize {
    let mut replacements = 0usize;
    for line in lines_in.iter_mut().skip(body_start_line) {
        for token in tokens {
            if token.is_empty() {
                continue;
            }
            let colored = lines::colstr(token, lines::Color::Macro);
            let mut search_at = 0usize;
            while let Some(rel) = line[search_at..].find(token) {
                let absolute = search_at + rel;
                line.replace_range(absolute..absolute + token.len(), &colored);
                search_at = absolute + colored.len();
                replacements += 1;
            }
        }
    }
    replacements
}

fn apply_item_index_visualizer(lines_in: &mut [String]) -> usize {
    let mut inserted = 0usize;
    let tag_prefix = format!("{}{}", lines::COLOR_ON, lines::COLOR_ADDR as char);

    for line in lines_in.iter_mut() {
        let mut offset = 0usize;
        while let Some(rel) = line[offset..].find(&tag_prefix) {
            let pos = offset + rel;
            let tag_end = pos + 2 + lines::COLOR_ADDR_SIZE as usize;
            if tag_end > line.len() {
                offset = pos + tag_prefix.len();
                continue;
            }

            let raw_index = line[pos + 2..tag_end].to_string();
            let annotation = lines::colstr(&format!("<{}>", raw_index), lines::Color::AutoComment);
            line.insert_str(pos, &annotation);
            offset = pos + annotation.len() + tag_prefix.len() + lines::COLOR_ADDR_SIZE as usize;
            inserted += 1;
        }
    }

    inserted
}

fn lvars_info_preview(
    decompiled: &decompiler::DecompiledFunction,
) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for variable in decompiled.variables()? {
        if variable.has_user_name {
            continue;
        }
        if !variable
            .name
            .chars()
            .next()
            .map(|c| c == 'v' || c == 'a')
            .unwrap_or(false)
        {
            continue;
        }

        let role = if variable.is_argument { "arg" } else { "local" };
        let proposed = if variable.is_argument {
            format!("{}_a{}", variable.name, variable.width)
        } else {
            format!("{}_l{}", variable.name, variable.width)
        };
        out.push((
            variable.name,
            format!("{} ({} bytes, {})", proposed, variable.width, role),
        ));
    }
    Ok(out)
}

fn function_name(address: u64) -> String {
    function::name_at(address).unwrap_or_else(|_| format!("sub_{address:x}"))
}

fn expand_hierarchy(root: u64, depth_limit: usize, callers: bool) -> Vec<HierarchyNode> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((root, 0usize));
    seen.insert(root);

    while let Some((current, depth)) = queue.pop_front() {
        if depth > 0 {
            out.push(HierarchyNode {
                depth,
                address: current,
                name: function_name(current),
            });
        }

        if depth >= depth_limit {
            continue;
        }

        let next = if callers {
            function::callers(current).unwrap_or_default()
        } else {
            function::callees(current).unwrap_or_default()
        };

        let mut ordered = BTreeSet::new();
        for address in next {
            ordered.insert(address);
        }

        for address in ordered {
            if seen.insert(address) {
                queue.push_back((address, depth + 1));
            }
        }
    }

    out
}

fn render_hierarchy(title: &str, nodes: &[HierarchyNode], root_name: &str, root: u64) -> String {
    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push_str("----------------\n");
    out.push_str(&format!("depth 0: {} (0x{:x})\n", root_name, root));
    if nodes.is_empty() {
        out.push_str("  <none>\n");
        return out;
    }

    for node in nodes {
        let indent = "  ".repeat(node.depth);
        out.push_str(&format!(
            "{}- depth {}: {} (0x{:x})\n",
            indent, node.depth, node.name, node.address
        ));
    }
    out
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;
    if !decompiler::available()? {
        return Err(Error::unsupported(
            "Hex-Rays decompiler is unavailable on this host",
        ));
    }

    let target = choose_target_function(&options)?;
    let target_name = target.name().to_string();
    let decompiled = decompiler::decompile(target.start())?;

    let header_count = decompiled.header_line_count()?.max(0) as usize;
    let mut raw_lines = decompiled.raw_lines()?;

    let token_replacements = apply_token_colorizer(&mut raw_lines, header_count, &options.tokens);
    let item_annotations = if options.item_index {
        apply_item_index_visualizer(&mut raw_lines)
    } else {
        0
    };

    let rendered_lines = if options.show_tags {
        raw_lines.clone()
    } else {
        raw_lines
            .iter()
            .map(|line| lines::tag_remove(line))
            .collect::<Vec<String>>()
    };

    let lvar_preview = lvars_info_preview(&decompiled)?;
    let callees = expand_hierarchy(target.start(), options.hierarchy_depth, false);
    let callers = expand_hierarchy(target.start(), options.hierarchy_depth, true);

    let mut report = String::new();
    report.push_str("abyss_port_plugin (Rust adaptation)\n");
    report.push_str(&format!("input: {}\n", options.input));
    report.push_str(&format!(
        "target: {} (0x{:x})\n",
        target_name,
        target.start()
    ));
    report.push_str(&format!("pseudocode_lines: {}\n", rendered_lines.len()));
    report.push_str(&format!("header_lines: {}\n", header_count));
    report.push_str("\nActive filter subset\n");
    report.push_str("--------------------\n");
    report.push_str("token_colorizer: ON\n");
    report.push_str(&format!(
        "item_index: {}\n",
        if options.item_index { "ON" } else { "OFF" }
    ));
    report.push_str("lvars_info (preview): ON\n");
    report.push_str("hierarchy: ON\n");
    report.push_str("signed_ops/item_ctype/lvars_alias/item_sync: OFF (host/UI-dependent)\n");
    report.push_str(&format!("token_replacements: {}\n", token_replacements));
    report.push_str(&format!("item_index_annotations: {}\n", item_annotations));

    report.push_str("\nPseudocode preview\n");
    report.push_str("------------------\n");
    for (line_number, line) in rendered_lines.iter().take(options.max_lines).enumerate() {
        report.push_str(&format!("{:>4}: {}\n", line_number + 1, line));
    }
    if rendered_lines.len() > options.max_lines {
        report.push_str(&format!(
            "... truncated {} additional lines\n",
            rendered_lines.len() - options.max_lines
        ));
    }

    report.push_str("\nLvars info preview\n");
    report.push_str("------------------\n");
    if lvar_preview.is_empty() {
        report.push_str("<none>\n");
    } else {
        for (old_name, preview) in lvar_preview.iter().take(40) {
            report.push_str(&format!("{} -> {}\n", old_name, preview));
        }
        if lvar_preview.len() > 40 {
            report.push_str(&format!(
                "... {} additional variable(s) omitted\n",
                lvar_preview.len() - 40
            ));
        }
    }

    report.push('\n');
    report.push_str(&render_hierarchy(
        "Hierarchy: Callees",
        &callees,
        &target_name,
        target.start(),
    ));
    report.push('\n');
    report.push_str(&render_hierarchy(
        "Hierarchy: Callers",
        &callers,
        &target_name,
        target.start(),
    ));

    write_output(options.output.as_deref(), &report)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
