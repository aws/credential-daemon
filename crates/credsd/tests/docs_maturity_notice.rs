//! Every user-facing document opens with the README's maturity notice, byte for byte
//! (user-documentation Requirements 1.1, 1.4, 1.5). Specs and design notes are maintainer
//! material and are not checked.

use std::path::{Path, PathBuf};

const OPEN: &str = "<!-- maturity-notice -->";
const CLOSE: &str = "<!-- /maturity-notice -->";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The marked block's contents, when it is the document's first content.
fn leading_notice(text: &str) -> Option<&str> {
    let (block, _) = text.trim_start().strip_prefix(OPEN)?.split_once(CLOSE)?;
    Some(block)
}

fn documents(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !matches!(
                path.file_name().and_then(|n| n.to_str()),
                Some("specs" | "design")
            ) {
                documents(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

#[test]
fn every_document_opens_with_the_canonical_notice() {
    let root = repo_root();
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");
    let canonical = leading_notice(&readme).expect("README.md must open with the notice");

    let mut docs = Vec::new();
    documents(&root.join("docs"), &mut docs);
    let problems: Vec<String> = docs
        .iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            match leading_notice(&text) {
                Some(notice) if notice == canonical => None,
                Some(_) => Some(format!("{}: notice differs from README.md", path.display())),
                None => Some(format!("{}: does not open with the notice", path.display())),
            }
        })
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
