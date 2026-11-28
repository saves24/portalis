//! Reading the `key = value` configuration files recipes and the panel use.
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Line-oriented settings: `key = value`, comma separated lists, `<<END` blocks
/// for multi-line text, `#` comments.
#[derive(Debug, Default, Clone)]
pub struct Conf {
    values: BTreeMap<String, Vec<String>>,
    blocks: std::collections::BTreeSet<String>,
}

impl Conf {
    pub fn parse(text: &str) -> Result<Self> {
        Self::parse_with(text, &[])
    }

    /// `repeatable` lists keys that may appear more than once.
    pub fn parse_with(text: &str, repeatable: &[&str]) -> Result<Self> {
        let mut conf = Self::default();
        let lines: Vec<&str> = text.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index].trim();
            let number = index + 1;
            index += 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, raw)) = line.split_once('=') else {
                bail!("line {number}: expected key = value");
            };
            let key = key.trim();
            if key.is_empty() {
                bail!("line {number}: empty key");
            }
            if !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
            {
                bail!("line {number}: invalid key {key}");
            }
            let value = strip_comment(raw).trim();
            let (body, block) = if let Some(marker) = value.strip_prefix("<<") {
                let marker = marker.trim();
                if marker.is_empty() {
                    bail!("line {number}: empty block marker");
                }
                let mut body = String::new();
                loop {
                    let Some(next) = lines.get(index) else {
                        bail!("line {number}: unterminated block {marker}");
                    };
                    index += 1;
                    if next.trim_end() == marker {
                        break;
                    }
                    body.push_str(next);
                    body.push('\n');
                }
                (body, true)
            } else {
                (value.to_string(), false)
            };
            if block {
                conf.blocks.insert(key.to_string());
            }
            let slot = conf.values.entry(key.to_string()).or_default();
            if !slot.is_empty() && !repeatable.contains(&key) {
                bail!("line {number}: duplicate key {key}");
            }
            slot.push(body);
        }
        Ok(conf)
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.last(key)
    }

    pub fn all(&self, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut index = 0;
        if let Some(values) = self.values.get(key) {
            for value in values {
                out.push(self.render(key, value, index));
                index += 1;
            }
        }
        out
    }

    fn last(&self, key: &str) -> Option<String> {
        let values = self.values.get(key)?;
        let index = values.len().saturating_sub(1);
        values
            .get(index)
            .map(|value| self.render(key, value, index))
    }

    fn render(&self, key: &str, value: &str, _index: usize) -> String {
        if self.blocks.contains(key) {
            value.to_string()
        } else {
            unquote(value)
        }
    }

    pub fn require(&self, key: &str) -> Result<String> {
        match self.get(key) {
            Some(value) if !value.is_empty() => Ok(value),
            _ => bail!("missing {key}"),
        }
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        match self.last(key) {
            Some(raw) => split_list(&raw),
            None => Vec::new(),
        }
    }

    pub fn flag(&self, key: &str, default: bool) -> Result<bool> {
        match self.last(key) {
            None => Ok(default),
            Some(value) if value == "true" => Ok(true),
            Some(value) if value == "false" => Ok(false),
            Some(other) => bail!("{key} must be true or false, found {other}"),
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(|key| key.as_str())
    }
}

/// Cuts a trailing `#` comment, ignoring `#` inside double quotes.
pub(super) fn strip_comment(value: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (c, quote) {
            ('\\', _) => escaped = true,
            ('\'' | '"', None) => quote = Some(c),
            ('\'' | '"', Some(open)) if open == c => quote = None,
            // a '#' only starts a comment outside a quoted value
            ('#', None) => return &value[..index],
            _ => {}
        }
    }
    value
}

/// Reads a settings file; a missing file yields empty settings.
pub fn load_conf(path: &Path) -> Result<Conf> {
    match std::fs::read_to_string(path) {
        Ok(text) => Conf::parse(&text).with_context(|| format!("parsing {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Conf::default()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

pub(super) fn unquote(value: &str) -> String {
    let value = value.trim();
    let quoted = value.len() >= 2
        && (value.starts_with('"') || value.starts_with('\''))
        && value.ends_with(value.chars().next().unwrap_or(' '));
    if quoted {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => break,
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        value.to_string()
    }
}

pub(super) fn split_list(raw: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in raw.chars() {
        match (c, quote) {
            ('\'' | '"', None) => {
                quote = Some(c);
                current.push(c);
            }
            ('\'' | '"', Some(open)) if open == c => {
                quote = None;
                current.push(c);
            }
            (',', None) => {
                items.push(unquote(current.trim()));
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        items.push(unquote(current.trim()));
    }
    items.into_iter().filter(|item| !item.is_empty()).collect()
}
