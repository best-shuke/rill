//! PROCESS-NAME-REGEX, PROCESS-PATH-REGEX, PROCESS-NAME-WILDCARD and
//! PROCESS-PATH-WILDCARD — mihomo's pattern forms of the process rules.
//!
//! upstream: `rules/common/process.go`. Regexes match case-insensitively
//! anywhere in the name or path (`regexp2.IgnoreCase`, unanchored);
//! wildcards are anchored, case-insensitive, `*` for any run of characters
//! and `?` for exactly one (`component/wildcard`).

use rill_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

enum Matcher {
    Regex(regex::Regex),
    /// Lowercased pattern.
    Wildcard(Box<str>),
}

pub struct ProcessPatternRule {
    payload: SmolStr,
    adapter: Adapter,
    rule_type: RuleType,
    matcher: Matcher,
}

impl ProcessPatternRule {
    /// `rule_type` is one of the four pattern process rule types.
    pub fn new(payload: &str, adapter: &str, rule_type: RuleType) -> Result<Self, String> {
        let matcher = match rule_type {
            RuleType::ProcessNameRegex | RuleType::ProcessPathRegex => Matcher::Regex(
                regex::RegexBuilder::new(payload)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| format!("invalid {rule_type} '{payload}': {e}"))?,
            ),
            RuleType::ProcessNameWildcard | RuleType::ProcessPathWildcard => {
                Matcher::Wildcard(payload.to_lowercase().into())
            }
            other => return Err(format!("{other} is not a process pattern rule")),
        };
        Ok(Self {
            payload: payload.into(),
            adapter: intern_adapter(adapter),
            rule_type,
            matcher,
        })
    }

    fn on_path(&self) -> bool {
        matches!(
            self.rule_type,
            RuleType::ProcessPathRegex | RuleType::ProcessPathWildcard
        )
    }
}

/// mihomo's wildcard match: `*` any run (possibly empty), `?` one character,
/// anything else itself.
pub fn wildcard_match(pattern: &str, s: &str) -> bool {
    if pattern.is_empty() {
        return s.is_empty();
    }
    if pattern == "*" || pattern == s {
        return true;
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

impl Rule for ProcessPatternRule {
    fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let target: &str = if self.on_path() {
            &metadata.process_path
        } else {
            &metadata.process
        };
        match &self.matcher {
            Matcher::Regex(re) => re.is_match(target),
            Matcher::Wildcard(pattern) => wildcard_match(pattern, &target.to_lowercase()),
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_find_process(&self) -> bool {
        rill_common::process_lookup::PROCESS_LOOKUP_SUPPORTED
    }

    fn never_matches(&self) -> bool {
        !rill_common::process_lookup::process_info_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(process: &str, path: &str) -> Metadata {
        Metadata {
            process: process.into(),
            process_path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn name_regex_is_unanchored_and_case_insensitive() {
        let r = ProcessPatternRule::new("telegram", "PROXY", RuleType::ProcessNameRegex).unwrap();
        assert!(r.match_metadata(&meta("Telegram Desktop", ""), &RuleMatchHelper));
        assert!(!r.match_metadata(&meta("curl", "/usr/bin/telegram"), &RuleMatchHelper));
    }

    #[test]
    fn path_regex_reads_the_path() {
        let r =
            ProcessPatternRule::new(".*bin/wget$", "PROXY", RuleType::ProcessPathRegex).unwrap();
        assert!(r.match_metadata(&meta("wget", "/usr/bin/wget"), &RuleMatchHelper));
        assert!(!r.match_metadata(&meta("wget", ""), &RuleMatchHelper));
    }

    #[test]
    fn wildcards() {
        let r = ProcessPatternRule::new("*Telegram*", "P", RuleType::ProcessNameWildcard).unwrap();
        assert!(r.match_metadata(&meta("telegram-desktop", ""), &RuleMatchHelper));
        let r = ProcessPatternRule::new("/usr/*/c?rl", "P", RuleType::ProcessPathWildcard).unwrap();
        assert!(r.match_metadata(&meta("", "/usr/bin/curl"), &RuleMatchHelper));
        assert!(!r.match_metadata(&meta("", "/usr/bin/cuurl"), &RuleMatchHelper));
        assert!(wildcard_match("a*b*c", "axxbyyc"));
        assert!(!wildcard_match("a*b*c", "axxbyy"));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "a"));
    }

    #[test]
    fn invalid_regex_is_an_error() {
        assert!(ProcessPatternRule::new("(", "P", RuleType::ProcessNameRegex).is_err());
    }
}
