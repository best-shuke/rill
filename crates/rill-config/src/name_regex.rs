//! Regular expressions over proxy names, with mihomo's dialect.
//!
//! mihomo compiles `filter`, `exclude-filter` and `override.proxy-name`
//! patterns with `regexp2`, a backtracking engine that understands
//! look-around (`^((?!香港).)*$` is the stock "everything but Hong Kong"
//! filter of most subscription templates). The `regex` crate has no
//! look-around, so a pattern it rejects is compiled again with
//! `fancy-regex`; everything else keeps the linear-time engine.
//!
//! A filter string may hold several patterns separated by a backtick, as
//! in mihomo: a name passes when any of them matches, and members are
//! ordered by the first pattern they match.

use std::borrow::Cow;

#[derive(Clone, Debug)]
pub enum NameRegex {
    Plain(regex::Regex),
    Fancy(Box<fancy_regex::Regex>),
}

impl NameRegex {
    /// Compile `pattern`, falling back to the backtracking engine only when
    /// the linear one cannot express it.
    pub fn new(pattern: &str) -> Result<Self, String> {
        match regex::Regex::new(pattern) {
            Ok(re) => Ok(Self::Plain(re)),
            Err(plain_err) => match fancy_regex::Regex::new(pattern) {
                Ok(re) => Ok(Self::Fancy(Box::new(re))),
                // Report the linear engine's error: it is the more precise
                // one for a pattern neither engine accepts.
                Err(_) => Err(plain_err.to_string()),
            },
        }
    }

    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            Self::Plain(re) => re.is_match(haystack),
            // A match that exhausts the backtrack limit counts as no match,
            // as regexp2's timeout does.
            Self::Fancy(re) => re.is_match(haystack).unwrap_or(false),
        }
    }

    /// Replace every match, expanding `$1` / `${name}` in `target`.
    pub fn replace_all<'h>(&self, haystack: &'h str, target: &str) -> Cow<'h, str> {
        match self {
            Self::Plain(re) => re.replace_all(haystack, target),
            Self::Fancy(re) => re.replace_all(haystack, target),
        }
    }
}

/// A backtick-separated list of [`NameRegex`] patterns.
#[derive(Clone, Debug, Default)]
pub struct NameRegexSet(Vec<NameRegex>);

impl NameRegexSet {
    /// Compile a mihomo filter string. `None` and `""` give an empty set.
    pub fn parse(raw: Option<&str>, field: &str) -> Result<Self, String> {
        let Some(raw) = raw.filter(|s| !s.is_empty()) else {
            return Ok(Self::default());
        };
        raw.split('`')
            .map(|p| NameRegex::new(p).map_err(|e| format!("{field} regex error: {e}")))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether any pattern matches `name`.
    pub fn any_match(&self, name: &str) -> bool {
        self.0.iter().any(|re| re.is_match(name))
    }

    /// Indices into `names` of the entries any pattern matches, grouped by
    /// the first pattern each matches (mihomo's member order), without
    /// repeats. An empty set keeps every entry in its order.
    pub fn select<'a>(&self, names: impl Iterator<Item = &'a str> + Clone) -> Vec<usize> {
        if self.0.is_empty() {
            return names.enumerate().map(|(i, _)| i).collect();
        }
        let mut taken = std::collections::HashSet::new();
        let mut out = Vec::new();
        for re in &self.0 {
            for (i, name) in names.clone().enumerate() {
                if re.is_match(name) && taken.insert(i) {
                    out.push(i);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn look_around_falls_back_to_the_backtracking_engine() {
        let re = NameRegex::new("^((?!港).)*$").unwrap();
        assert!(matches!(re, NameRegex::Fancy(_)));
        assert!(re.is_match("日本 01"));
        assert!(!re.is_match("香港 01"));
    }

    #[test]
    fn plain_patterns_stay_on_the_linear_engine() {
        let re = NameRegex::new("(?i)港|hk").unwrap();
        assert!(matches!(re, NameRegex::Plain(_)));
        assert!(re.is_match("HK-01"));
    }

    #[test]
    fn invalid_pattern_is_an_error() {
        assert!(NameRegex::new("(").is_err());
    }

    #[test]
    fn backtick_list_orders_by_pattern() {
        let set = NameRegexSet::parse(Some("日本`香港"), "filter").unwrap();
        let names = ["香港 01", "日本 01", "美国 01", "香港 02"];
        let picked = set.select(names.iter().copied());
        assert_eq!(picked, vec![1, 0, 3]);
        assert!(set.any_match("香港 02"));
        assert!(!set.any_match("美国 01"));
    }

    #[test]
    fn empty_set_keeps_everything() {
        let set = NameRegexSet::parse(Some(""), "filter").unwrap();
        assert!(set.is_empty());
        assert_eq!(set.select(["a", "b"].iter().copied()), vec![0, 1]);
    }

    #[test]
    fn replace_expands_groups() {
        let re = NameRegex::new("IPLC-(.*?)倍").unwrap();
        assert_eq!(re.replace_all("IPLC-2倍", "iplc x $1"), "iplc x 2");
    }
}
