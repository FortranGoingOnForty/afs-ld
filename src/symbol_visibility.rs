use std::fs;
use std::path::{Path, PathBuf};

use crate::LinkOptions;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SymbolVisibilityPolicy {
    exported: Vec<String>,
    unexported: Vec<String>,
}

impl SymbolVisibilityPolicy {
    pub(crate) fn from_opts(opts: &LinkOptions) -> Result<Self, SymbolVisibilityError> {
        let mut exported = opts.exported_symbols.clone();
        let mut unexported = opts.unexported_symbols.clone();
        for path in &opts.exported_symbols_lists {
            exported.extend(read_symbol_patterns(path)?);
        }
        for path in &opts.unexported_symbols_lists {
            unexported.extend(read_symbol_patterns(path)?);
        }
        Ok(Self {
            exported,
            unexported,
        })
    }

    pub(crate) fn hides(&self, name: &str) -> bool {
        if !self.exported.is_empty()
            && !self
                .exported
                .iter()
                .any(|pattern| wildcard_matches(pattern, name))
        {
            return true;
        }
        self.unexported
            .iter()
            .any(|pattern| wildcard_matches(pattern, name))
    }
}

#[derive(Debug)]
pub(crate) struct SymbolVisibilityError {
    path: PathBuf,
    source: std::io::Error,
}

impl SymbolVisibilityError {
    pub(crate) fn into_parts(self) -> (PathBuf, String) {
        (self.path, self.source.to_string())
    }
}

fn read_symbol_patterns(path: &Path) -> Result<Vec<String>, SymbolVisibilityError> {
    let contents = fs::read_to_string(path).map_err(|source| SymbolVisibilityError {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut p = 0usize;
    let mut v = 0usize;
    let mut star = None;
    let mut backtrack = 0usize;

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            backtrack = v;
        } else if let Some(star_idx) = star {
            p = star_idx + 1;
            backtrack += 1;
            v = backtrack;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_allowlist_and_unexported_denylist_compose() {
        let policy = SymbolVisibilityPolicy {
            exported: vec!["_keep*".into(), "_blocked".into()],
            unexported: vec!["*_blocked".into()],
        };

        assert!(!policy.hides("_keeper"));
        assert!(policy.hides("_other"));
        assert!(policy.hides("_blocked"));
    }
}
