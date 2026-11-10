//! Completeness check between a clap command tree and `docs/reference/commands.md`.
//!
//! Each command has a `### <path>` section (`### creds`, `### creds bootstrap aws-idc-sso`). Every
//! long flag a command defines must appear in its section, and every flag in a section's table
//! rows (`| `--flag` ...`) must exist on that command or on the binary's root. Shared by the
//! `creds` and `credsd` test modules via `#[path]`, so neither crate needs another dependency.

use clap::Command;

pub fn discrepancies(root: &Command, doc: &str) -> Vec<String> {
    let mut expected = Vec::new();
    collect(root, root.get_name().to_string(), &mut expected);
    let globals = long_flags(root);
    let sections = sections(doc, root.get_name());

    let mut out = Vec::new();
    for (path, flags) in &expected {
        let Some((_, body)) = sections.iter().find(|(h, _)| h == path) else {
            out.push(format!("missing section `### {path}`"));
            continue;
        };
        for flag in flags {
            if !body.contains(&format!("`--{flag}")) {
                out.push(format!("`{path}`: --{flag} is not documented"));
            }
        }
        for flag in documented_flags(body) {
            if !flags.contains(&flag) && !globals.contains(&flag) {
                out.push(format!(
                    "`{path}`: documents --{flag}, which does not exist"
                ));
            }
        }
    }
    for (heading, _) in &sections {
        if !expected.iter().any(|(path, _)| path == heading) {
            out.push(format!("section `### {heading}` names no command"));
        }
    }
    out
}

fn collect(cmd: &Command, path: String, out: &mut Vec<(String, Vec<String>)>) {
    out.push((path.clone(), long_flags(cmd)));
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        collect(sub, format!("{path} {}", sub.get_name()), out);
    }
}

fn long_flags(cmd: &Command) -> Vec<String> {
    cmd.get_arguments()
        .filter(|a| !a.is_hide_set())
        .filter_map(|a| a.get_long().map(str::to_string))
        .collect()
}

/// `(heading, body)` for every `### <bin>...` section; a body ends at the next heading.
///
/// A `#` inside a code fence is a shell comment, not a heading. Reading it as one would end the
/// section early and drop the flag table below it, which hides documented flags that do not
/// exist as well as reporting real ones missing.
fn sections(doc: &str, bin: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut in_section = false;
    let mut fenced = false;
    for line in doc.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
        } else if let Some(heading) = line.strip_prefix("### ").filter(|_| !fenced) {
            let heading = heading.trim().trim_matches('`');
            if heading == bin || heading.starts_with(&format!("{bin} ")) {
                out.push((heading.to_string(), String::new()));
                in_section = true;
                continue;
            }
        }
        if !fenced && line.starts_with('#') {
            in_section = false;
        } else if let Some((_, body)) = out.last_mut().filter(|_| in_section) {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

fn documented_flags(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("| `--"))
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell comment in the usage fence used to end the section, so the table below it was
    /// never read: real flags reported missing, and a bogus row never reported at all.
    #[test]
    fn a_hash_comment_inside_a_fence_does_not_end_the_section() {
        let cmd = Command::new("tool").arg(clap::Arg::new("real").long("real"));
        let doc = "### tool\n\n```\n# a shell comment\ntool --real\n```\n\n\
                   | `--real` | real |\n| `--bogus` | not a flag |\n";
        assert_eq!(
            discrepancies(&cmd, doc),
            vec!["`tool`: documents --bogus, which does not exist".to_string()]
        );
    }
}
