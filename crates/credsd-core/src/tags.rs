//! Credential tags: `key = value` labels on a `credentials.toml` entry that `credential/list`
//! filters by.
//!
//! Tags describe a credential for its owner; they carry no authority. Nothing resolves, approves,
//! or refuses a credential because of a tag.

use std::collections::BTreeMap;

use crate::error::{DaemonError, Result};

/// A credential's tags. Ordered, so a rendered row and a written file are deterministic.
pub type Tags = BTreeMap<String, String>;

/// A `credential/list` tag filter. `key -> Some(value)` requires that exact pair; `key -> None`
/// requires only that the key is present, with any value. On the wire the key-only form is a
/// JSON `null`: `{"team": "payments", "stage": null}`.
pub type TagFilter = BTreeMap<String, Option<String>>;

/// Most tags one credential may carry.
pub const MAX_TAGS: usize = 32;
/// Longest tag key, in bytes.
pub const MAX_KEY_LEN: usize = 63;
/// Longest tag value, in bytes.
pub const MAX_VALUE_LEN: usize = 256;

fn key_ok(key: &str) -> bool {
    let Some((first, rest)) = key.as_bytes().split_first() else {
        return false;
    };
    key.len() <= MAX_KEY_LEN
        && matches!(first, b'a'..=b'z' | b'0'..=b'9')
        && rest
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn value_ok(value: &str) -> bool {
    value.len() <= MAX_VALUE_LEN && value.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

fn bad_key(key: &str) -> DaemonError {
    DaemonError::config(format!(
        "tag key {key:?} must be 1-{MAX_KEY_LEN} of a-z 0-9 . _ - starting with a-z or 0-9"
    ))
}

/// `map` with every key folded to lowercase (ASCII `A` to `Z` only), as every input must be
/// before it is checked, stored, or compared (credential-tags 1.4). Values are untouched. Two
/// keys that fold to the same key are refused naming both spellings, never resolved (1.6).
pub fn fold<V>(map: BTreeMap<String, V>) -> Result<BTreeMap<String, V>> {
    let mut folded = BTreeMap::new();
    let mut spelled: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in map {
        let key = k.to_ascii_lowercase();
        if let Some(first) = spelled.get(&key) {
            return Err(collision(first, &k));
        }
        spelled.insert(key.clone(), k);
        folded.insert(key, v);
    }
    Ok(folded)
}

/// [`fold`] for a bare key list, such as `credential/tag`'s `unset`.
pub fn fold_keys(keys: Vec<String>) -> Result<Vec<String>> {
    let pairs = keys
        .into_iter()
        .map(|k| (k, ()))
        .collect::<BTreeMap<_, _>>();
    fold(pairs).map(|m| m.into_keys().collect())
}

fn collision(a: &str, b: &str) -> DaemonError {
    DaemonError::config(format!(
        "tag keys {a:?} and {b:?} are the same key once folded to lowercase"
    ))
}

/// Checks a key against the tag grammar. The error names the key.
pub fn validate_key(key: &str) -> Result<()> {
    key_ok(key).then_some(()).ok_or_else(|| bad_key(key))
}

/// Checks every key and value against the tag grammar and the count limit. The error names the
/// offending key and never the value.
pub fn validate(tags: &Tags) -> Result<()> {
    if tags.len() > MAX_TAGS {
        return Err(DaemonError::config(format!(
            "{} tags; the maximum is {MAX_TAGS}",
            tags.len()
        )));
    }
    for (k, v) in tags {
        validate_key(k)?;
        if !value_ok(v) {
            return Err(DaemonError::config(format!(
                "tag {k:?} value must be at most {MAX_VALUE_LEN} bytes of printable ASCII"
            )));
        }
    }
    Ok(())
}

/// `tags` [folded](fold), then [validated](validate): what every stored tag set must pass.
pub fn normalize(tags: Tags) -> Result<Tags> {
    let tags = fold(tags)?;
    validate(&tags)?;
    Ok(tags)
}

/// Checks a filter's keys and values against the same grammar as stored tags.
pub fn validate_filter(filter: &TagFilter) -> Result<()> {
    for (k, v) in filter {
        validate_key(k)?;
        if v.as_deref().is_some_and(|v| !value_ok(v)) {
            return Err(DaemonError::config(format!(
                "tag {k:?} value must be at most {MAX_VALUE_LEN} bytes of printable ASCII"
            )));
        }
    }
    Ok(())
}

/// Whether `tags` satisfies every entry of `filter`. An empty filter matches every credential.
pub fn matches(tags: &Tags, filter: &TagFilter) -> bool {
    filter.iter().all(|(k, want)| {
        tags.get(k)
            .is_some_and(|have| want.as_ref().is_none_or(|w| w == have))
    })
}

/// `old` with `set` applied and then `unset` removed, validated. A key in both `set` and `unset`
/// is refused by name; unsetting a key `old` lacks changes nothing.
pub fn apply(old: &Tags, set: &Tags, unset: &[String]) -> Result<Tags> {
    if let Some(k) = unset.iter().find(|k| set.contains_key(*k)) {
        return Err(DaemonError::config(format!(
            "tag {k:?} is both set and unset"
        )));
    }
    let mut tags = old.clone();
    tags.extend(set.iter().map(|(k, v)| (k.clone(), v.clone())));
    for k in unset {
        tags.remove(k);
    }
    validate(&tags)?;
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::btree_map;
    use proptest::prelude::*;

    fn key() -> impl Strategy<Value = String> {
        "[a-z0-9][a-z0-9._-]{0,62}"
    }

    fn value() -> impl Strategy<Value = String> {
        // Printable ASCII, space through tilde.
        "[ -~]{0,256}"
    }

    fn tags() -> impl Strategy<Value = Tags> {
        btree_map(key(), value(), 0..=MAX_TAGS)
    }

    /// A key that breaks the grammar in one of the ways a hand-edited file or a hostile caller
    /// would: wrong case, a leading separator, a control character, non-ASCII, or one byte too long.
    fn bad_key() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            "[a-z0-9]{0,10}[A-Z][a-z0-9]{0,10}",
            "[._-][a-z0-9]{0,10}",
            "[a-z0-9]{1,10}[\\x00-\\x1f\\x7f][a-z0-9]{0,10}",
            "[a-z0-9]{0,10}[\\u{80}-\\u{10ffff}][a-z0-9]{0,10}",
            "[a-z0-9 =\"'/]{0,10}[ =\"'/][a-z0-9]{0,10}",
            "[a-z0-9]{64,80}",
        ]
    }

    fn bad_value() -> impl Strategy<Value = String> {
        prop_oneof![
            "[ -~]{0,10}[\\x00-\\x1f\\x7f][ -~]{0,10}",
            "[ -~]{0,10}[\\u{80}-\\u{10ffff}][ -~]{0,10}",
            "[ -~]{257,300}",
        ]
    }

    /// `key` with the letters `upper` picks raised to uppercase, as a caller might spell it.
    fn recase(key: &str, upper: &[bool]) -> String {
        key.chars()
            .zip(upper.iter().chain(std::iter::repeat(&false)))
            .map(|(c, up)| if *up { c.to_ascii_uppercase() } else { c })
            .collect()
    }

    /// A key spelled with each of its letters in either case.
    fn any_case_key() -> impl Strategy<Value = String> {
        (key(), proptest::collection::vec(any::<bool>(), 63)).prop_map(|(k, up)| recase(&k, &up))
    }

    /// The review example for 3.3: two edits merge, the second overwriting only the key they share.
    #[test]
    fn two_edits_merge_rather_than_replace() {
        let pairs = |p: &[(&str, &str)]| -> Tags {
            p.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect()
        };
        let a = apply(&Tags::new(), &pairs(&[("foo", "a"), ("bar", "a")]), &[]).expect("A");
        let b = apply(&a, &pairs(&[("bar", "b"), ("baz", "b")]), &[]).expect("B");
        assert_eq!(b, pairs(&[("foo", "a"), ("bar", "b"), ("baz", "b")]));
    }

    proptest! {
        /// However a caller cases the keys, folding yields the lowercase set with every value
        /// byte for byte, and the folded set passes the grammar.
        #[test]
        fn folding_lowercases_keys_and_keeps_values(tags in tags(), up in proptest::collection::vec(any::<bool>(), 63)) {
            let spelled: Tags = tags.iter().map(|(k, v)| (recase(k, &up), v.clone())).collect();
            let folded = fold(spelled).expect("distinct keys refused");
            prop_assert!(validate(&folded).is_ok());
            prop_assert_eq!(folded, tags);
        }

        /// Folding maps `A` to `Z` and nothing else, so a non-ASCII or other byte is left for the
        /// grammar to refuse rather than rewritten into an accepted key.
        #[test]
        fn folding_touches_only_ascii_capitals(k in "\\PC{0,20}") {
            let folded = fold(Tags::from([(k.clone(), String::new())])).expect("one key");
            prop_assert_eq!(folded.into_keys().collect::<Vec<_>>(), vec![k.to_ascii_lowercase()]);
        }

        /// Two spellings of one key are refused naming both, never resolved to either value, and
        /// the error quotes neither value.
        #[test]
        fn two_spellings_of_one_key_are_refused_naming_both(k in "[a-z][a-z0-9._-]{0,62}", up in proptest::collection::vec(any::<bool>(), 63), other in tags()) {
            let mut up = up;
            up[0] = true;
            let loud = recase(&k, &up);
            let mut spelled = other;
            spelled.insert(k.clone(), "sk-planted-a".into());
            spelled.insert(loud.clone(), "sk-planted-b".into());
            let err = fold(spelled).expect_err("collision accepted").to_string();
            prop_assert!(err.contains(&format!("{k:?}")) && err.contains(&format!("{loud:?}")), "{err}");
            prop_assert!(!err.contains("sk-planted"), "error {err:?} quotes a value");
        }

        /// A filter folds the same way, keeping each condition's value or presence.
        #[test]
        fn a_filter_folds_like_tags(filter in btree_map(key(), proptest::option::of(value()), 0..8), up in proptest::collection::vec(any::<bool>(), 63)) {
            let spelled: TagFilter = filter.iter().map(|(k, v)| (recase(k, &up), v.clone())).collect();
            prop_assert_eq!(fold(spelled).expect("distinct keys refused"), filter);
        }

        /// `unset` keys fold too, and two spellings of one key in a list are refused.
        #[test]
        fn unset_keys_fold_and_collide(keys in proptest::collection::btree_set(key(), 0..8), up in proptest::collection::vec(any::<bool>(), 63), dup in any_case_key()) {
            let spelled: Vec<String> = keys.iter().map(|k| recase(k, &up)).collect();
            prop_assert_eq!(fold_keys(spelled).expect("distinct keys refused"), keys.iter().cloned().collect::<Vec<_>>());
            let lower = dup.to_ascii_lowercase();
            prop_assume!(lower != dup);
            prop_assert!(fold_keys(vec![lower, dup]).is_err());
        }

        /// credential-tags 3.3, as `credential/tag` runs it: `set` and `unset` arrive in any case,
        /// are folded, and merge into the existing set. A key in `set` takes its new value, a key in
        /// `unset` goes, and every other key keeps its value.
        #[test]
        fn an_edit_merges_into_the_existing_set(old in btree_map(key(), value(), 0..12), set in btree_map(key(), value(), 0..12), unset in proptest::collection::btree_set(key(), 0..12), up in proptest::collection::vec(any::<bool>(), 63)) {
            let unset: Vec<String> = unset.into_iter().filter(|k| !set.contains_key(k)).collect();
            let mut want = old.clone();
            for (k, v) in &set {
                want.insert(k.clone(), v.clone());
            }
            for k in &unset {
                want.remove(k);
            }
            prop_assume!(want.len() <= MAX_TAGS);
            let spelled_set: Tags = set.iter().map(|(k, v)| (recase(k, &up), v.clone())).collect();
            let spelled_unset: Vec<String> = unset.iter().map(|k| recase(k, &up)).collect();
            let got = apply(
                &old,
                &fold(spelled_set).expect("distinct keys"),
                &fold_keys(spelled_unset).expect("distinct keys"),
            );
            prop_assert_eq!(got.expect("disjoint edit"), want);
        }

        #[test]
        fn every_valid_tag_set_is_accepted(tags in tags()) {
            prop_assert!(validate(&tags).is_ok(), "rejected {tags:?}");
        }

        #[test]
        fn a_bad_key_is_rejected_by_name(mut tags in btree_map(key(), value(), 0..MAX_TAGS), bad in bad_key()) {
            tags.insert(bad.clone(), "v".into());
            let err = validate(&tags).expect_err("accepted a bad key").to_string();
            prop_assert!(err.contains(&format!("{bad:?}")), "error {err:?} does not name {bad:?}");
        }

        #[test]
        fn a_bad_value_is_rejected_naming_its_key(mut tags in btree_map(key(), value(), 0..MAX_TAGS), k in key(), bad in bad_value()) {
            tags.insert(k.clone(), format!("sk-planted{bad}"));
            let err = validate(&tags).expect_err("accepted a bad value").to_string();
            prop_assert!(err.contains(&format!("{k:?}")), "error {err:?} does not name {k:?}");
            prop_assert!(!err.contains("sk-planted"), "error {err:?} quotes the value");
        }

        #[test]
        fn more_than_the_limit_is_rejected(tags in btree_map(key(), value(), MAX_TAGS + 1..=MAX_TAGS + 8)) {
            prop_assert!(validate(&tags).is_err());
        }

        #[test]
        fn an_empty_filter_matches_everything(tags in tags()) {
            prop_assert!(matches(&tags, &TagFilter::new()));
        }

        /// Any filter drawn from a credential's own tags matches it, whether each entry names the
        /// value or only the key.
        #[test]
        fn a_filter_drawn_from_the_tags_matches(tags in tags(), picks in proptest::collection::vec((any::<bool>(), any::<bool>()), MAX_TAGS)) {
            let filter: TagFilter = tags
                .iter()
                .zip(picks)
                .filter(|(_, (take, _))| *take)
                .map(|((k, v), (_, key_only))| (k.clone(), (!key_only).then(|| v.clone())))
                .collect();
            prop_assert!(matches(&tags, &filter), "{filter:?} vs {tags:?}");
        }

        #[test]
        fn a_key_the_credential_lacks_never_matches(tags in tags(), k in key(), v in proptest::option::of(value())) {
            prop_assume!(!tags.contains_key(&k));
            let filter = TagFilter::from([(k, v)]);
            prop_assert!(!matches(&tags, &filter));
        }

        #[test]
        fn a_present_key_with_another_value_does_not_match(mut tags in tags(), k in key(), have in value(), want in value()) {
            prop_assume!(have != want);
            tags.insert(k.clone(), have);
            let filter = TagFilter::from([(k, Some(want))]);
            prop_assert!(!matches(&tags, &filter));
        }

        /// A key-only entry matches whatever value the credential holds for that key.
        #[test]
        fn a_key_only_entry_matches_any_value(mut tags in tags(), k in key(), have in value()) {
            tags.insert(k.clone(), have);
            prop_assert!(matches(&tags, &TagFilter::from([(k, None)])));
        }

        /// A key named in both halves of an edit is refused by name, whatever else the edit holds.
        #[test]
        fn a_key_in_both_set_and_unset_is_refused_by_name(old in tags(), set in btree_map(key(), value(), 0..8), k in key(), unset in proptest::collection::vec(key(), 0..8)) {
            let mut set = set;
            set.insert(k.clone(), "v".into());
            // `k` must be the only overlap: `apply` names the first one it finds.
            let mut unset = unset;
            unset.retain(|u| !set.contains_key(u));
            unset.push(k.clone());
            let err = apply(&old, &set, &unset).expect_err("overlap accepted").to_string();
            prop_assert!(err.contains(&format!("{k:?}")), "error {err:?} does not name {k:?}");
        }

        /// A disjoint edit yields exactly `old` overlaid with `set`, minus `unset`. Unsetting a key
        /// the credential lacks is not an error.
        #[test]
        fn a_disjoint_edit_sets_then_unsets(old in btree_map(key(), value(), 0..12), set in btree_map(key(), value(), 0..12), unset in proptest::collection::vec(key(), 0..12)) {
            prop_assume!(unset.iter().all(|k| !set.contains_key(k)));
            let mut want = old.clone();
            want.extend(set.clone());
            for k in &unset {
                want.remove(k);
            }
            prop_assume!(want.len() <= MAX_TAGS);
            prop_assert_eq!(apply(&old, &set, &unset).expect("disjoint edit"), want);
        }

        /// The result is held to the same grammar as a loaded file, so an edit cannot write a tag
        /// a load would refuse.
        #[test]
        fn an_edit_that_sets_a_bad_key_is_refused(old in btree_map(key(), value(), 0..8), bad in bad_key()) {
            prop_assert!(apply(&old, &Tags::from([(bad, "v".into())]), &[]).is_err());
        }

        #[test]
        fn an_edit_past_the_limit_is_refused(old in btree_map(key(), value(), MAX_TAGS..=MAX_TAGS), k in key()) {
            prop_assume!(!old.contains_key(&k));
            prop_assert!(apply(&old, &Tags::from([(k, "v".into())]), &[]).is_err());
        }
    }
}
