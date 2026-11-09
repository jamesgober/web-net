//! The route table: a segment trie compiled at build time.
//!
//! Static segments are tried first, then a parameter, then a wildcard; when
//! a branch fails further down, the next kind is tried. Each trie node is
//! visited at most once per lookup, so the work is bounded by the length of
//! the path and the size of the table, and a lookup allocates nothing.

use crate::url;

/// The most parameters (named and wildcard) one route pattern may have.
pub const MAX_PARAMS: usize = 8;

/// One segment of a route pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// A literal, in canonical encoding.
    Static(String),
    /// `:name`: one segment.
    Param(String),
    /// `*name`: the rest of the path, zero or more segments. Last only.
    Wildcard(String),
}

/// Why a pattern is refused at build time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PatternError {
    NotAbsolute,
    Empty,
    Dot,
    NoName,
    WildcardNotLast,
    TooManyParams,
    DuplicateName(String),
}

impl PatternError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::NotAbsolute => "a route path must start with '/'".into(),
            Self::Empty => "a route path has an empty segment ('//')".into(),
            Self::Dot => "a route path has a '.' or '..' segment".into(),
            Self::NoName => "a ':' or '*' segment needs a name".into(),
            Self::WildcardNotLast => "a '*' segment must be the last one".into(),
            Self::TooManyParams => format!("a route has more than {MAX_PARAMS} parameters"),
            Self::DuplicateName(n) => format!("the parameter name '{n}' is used twice"),
        }
    }
}

/// Parses a route pattern such as `/users/:id/files/*rest`. A trailing slash
/// is ignored: the site's policy decides how the URL is spelled.
pub(crate) fn parse(pattern: &str) -> Result<Vec<Part>, PatternError> {
    let Some(rest) = pattern.strip_prefix('/') else {
        return Err(PatternError::NotAbsolute);
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut parts = Vec::new();
    if rest.is_empty() {
        return Ok(parts);
    }
    let mut names: Vec<&str> = Vec::new();
    let segs: Vec<&str> = rest.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        let named = |n: &str| -> Result<String, PatternError> {
            if n.is_empty() {
                Err(PatternError::NoName)
            } else {
                Ok(n.to_owned())
            }
        };
        let part = if let Some(n) = seg.strip_prefix(':') {
            Part::Param(named(n)?)
        } else if let Some(n) = seg.strip_prefix('*') {
            if i + 1 != segs.len() {
                return Err(PatternError::WildcardNotLast);
            }
            Part::Wildcard(named(n)?)
        } else if seg.is_empty() {
            return Err(PatternError::Empty);
        } else if *seg == "." || *seg == ".." {
            return Err(PatternError::Dot);
        } else {
            Part::Static(url::canonical_literal(seg))
        };
        if let Part::Param(n) | Part::Wildcard(n) = &part {
            if names.contains(&n.as_str()) {
                return Err(PatternError::DuplicateName(n.clone()));
            }
            names.push(&seg[1..]);
            if names.len() > MAX_PARAMS {
                return Err(PatternError::TooManyParams);
            }
        }
        parts.push(part);
    }
    Ok(parts)
}

/// The parameter names of a parsed pattern, in order.
pub(crate) fn names(parts: &[Part]) -> Vec<Box<str>> {
    parts
        .iter()
        .filter_map(|p| match p {
            Part::Param(n) | Part::Wildcard(n) => Some(n.as_str().into()),
            Part::Static(_) => None,
        })
        .collect()
}

#[derive(Debug, Default)]
struct Node {
    /// Sorted by literal for binary search.
    statics: Vec<(Box<str>, u32)>,
    param: Option<u32>,
    wildcard: Option<u32>,
    endpoint: Option<u32>,
}

/// Captured parameter spans, as byte ranges into the matched path.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Captures {
    spans: [(u32, u32); MAX_PARAMS],
    len: u8,
}

impl Captures {
    #[inline]
    fn push(&mut self, s: usize, e: usize) {
        // Patterns are capped at MAX_PARAMS at build, so this cannot overflow.
        if (self.len as usize) < MAX_PARAMS {
            self.spans[self.len as usize] = (s as u32, e as u32);
            self.len += 1;
        }
    }

    #[inline]
    pub(crate) fn get(&self, i: usize) -> Option<(usize, usize)> {
        if i < self.len as usize {
            let (s, e) = self.spans[i];
            Some((s as usize, e as usize))
        } else {
            None
        }
    }
}

/// The compiled table: path patterns to endpoint numbers.
#[derive(Debug)]
pub(crate) struct Trie {
    nodes: Vec<Node>,
}

impl Default for Trie {
    fn default() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }
}

impl Trie {
    /// Inserts a pattern; returns the endpoint number of the pattern (new or
    /// existing: two patterns that differ only in parameter names share it).
    pub(crate) fn insert(&mut self, parts: &[Part], next_endpoint: u32) -> u32 {
        let mut at = 0usize;
        for part in parts {
            at = match part {
                Part::Static(lit) => {
                    let node = &self.nodes[at];
                    match node
                        .statics
                        .binary_search_by(|(l, _)| l.as_ref().cmp(lit.as_str()))
                    {
                        Ok(i) => node.statics[i].1 as usize,
                        Err(i) => {
                            let id = self.nodes.len() as u32;
                            self.nodes.push(Node::default());
                            self.nodes[at].statics.insert(i, (lit.as_str().into(), id));
                            id as usize
                        }
                    }
                }
                Part::Param(_) => match self.nodes[at].param {
                    Some(id) => id as usize,
                    None => {
                        let id = self.nodes.len() as u32;
                        self.nodes.push(Node::default());
                        self.nodes[at].param = Some(id);
                        id as usize
                    }
                },
                Part::Wildcard(_) => {
                    return *self.nodes[at].wildcard.get_or_insert(next_endpoint);
                }
            };
        }
        *self.nodes[at].endpoint.get_or_insert(next_endpoint)
    }

    /// Looks up a site-relative canonical path (`/`, `/a/b`, a trailing
    /// slash already handled). Returns the endpoint and captures.
    pub(crate) fn find(&self, path: &str) -> Option<(u32, Captures)> {
        let mut caps = Captures::default();
        let body = path.strip_prefix('/').unwrap_or(path);
        let ep = self.walk(0, path.as_bytes(), path.len() - body.len(), &mut caps)?;
        Some((ep, caps))
    }

    /// `pos` is the byte offset in `path` where the next segment starts
    /// (`path.len()` when no segment is left).
    fn walk(&self, at: usize, path: &[u8], pos: usize, caps: &mut Captures) -> Option<u32> {
        let node = &self.nodes[at];
        if pos >= path.len() {
            if let Some(ep) = node.endpoint {
                return Some(ep);
            }
            if let Some(ep) = node.wildcard {
                caps.push(path.len(), path.len());
                return Some(ep);
            }
            return None;
        }
        let end = path[pos..]
            .iter()
            .position(|&c| c == b'/')
            .map_or(path.len(), |i| pos + i);
        let seg = &path[pos..end];
        let next = if end < path.len() {
            end + 1
        } else {
            path.len()
        };
        if let Ok(i) = node
            .statics
            .binary_search_by(|(l, _)| l.as_bytes().cmp(seg))
        {
            let mark = caps.len;
            if let Some(ep) = self.walk(node.statics[i].1 as usize, path, next, caps) {
                return Some(ep);
            }
            caps.len = mark;
        }
        if let Some(p) = node.param {
            let mark = caps.len;
            caps.push(pos, end);
            if let Some(ep) = self.walk(p as usize, path, next, caps) {
                return Some(ep);
            }
            caps.len = mark;
        }
        if let Some(ep) = node.wildcard {
            caps.push(pos, path.len());
            return Some(ep);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(patterns: &[&str]) -> Trie {
        let mut t = Trie::default();
        for (i, p) in patterns.iter().enumerate() {
            let parts = parse(p).unwrap();
            assert_eq!(t.insert(&parts, i as u32), i as u32, "{p}");
        }
        t
    }

    fn find<'a>(t: &Trie, path: &'a str) -> Option<(u32, Vec<&'a str>)> {
        let (ep, caps) = t.find(path)?;
        let v = (0..MAX_PARAMS)
            .filter_map(|i| caps.get(i))
            .map(|(s, e)| &path[s..e])
            .collect();
        Some((ep, v))
    }

    #[test]
    fn test_precedence_static_param_wildcard() {
        let t = table(&["/users/new", "/users/:id", "/users/*rest", "/"]);
        assert_eq!(find(&t, "/users/new"), Some((0, vec![])));
        assert_eq!(find(&t, "/users/7"), Some((1, vec!["7"])));
        assert_eq!(find(&t, "/users/7/x"), Some((2, vec!["7/x"])));
        assert_eq!(find(&t, "/"), Some((3, vec![])));
        assert_eq!(find(&t, "/nope"), None);
    }

    #[test]
    fn test_backtracks_from_static_to_param() {
        let t = table(&["/users/new", "/users/:id/edit"]);
        assert_eq!(find(&t, "/users/new/edit"), Some((1, vec!["new"])));
        assert_eq!(find(&t, "/users/new"), Some((0, vec![])));
        assert_eq!(find(&t, "/users/9"), None);
    }

    #[test]
    fn test_wildcard_matches_empty_rest() {
        let t = table(&["/static/*path"]);
        assert_eq!(find(&t, "/static"), Some((0, vec![""])));
        assert_eq!(find(&t, "/static/a/b.css"), Some((0, vec!["a/b.css"])));
    }

    #[test]
    fn test_shared_endpoint_for_renamed_params() {
        let mut t = Trie::default();
        assert_eq!(t.insert(&parse("/u/:id").unwrap(), 0), 0);
        assert_eq!(t.insert(&parse("/u/:name").unwrap(), 1), 0);
    }

    #[test]
    fn test_literals_are_canonical() {
        let t = table(&["/café", "/a b"]);
        assert_eq!(find(&t, "/caf%C3%A9"), Some((0, vec![])));
        assert_eq!(find(&t, "/a%20b"), Some((1, vec![])));
    }

    mod props {
        use proptest::prelude::*;

        use super::super::*;

        /// Whether `parts` matches the segments `segs` (the plain
        /// definition, without the trie).
        fn matches(parts: &[Part], segs: &[&str]) -> bool {
            match (parts.first(), segs.first()) {
                (None, None) => true,
                (Some(Part::Wildcard(_)), _) => true,
                (Some(Part::Static(l)), Some(s)) => l == s && matches(&parts[1..], &segs[1..]),
                (Some(Part::Param(_)), Some(_)) => matches(&parts[1..], &segs[1..]),
                _ => false,
            }
        }

        fn pattern() -> impl Strategy<Value = String> {
            let seg = prop_oneof![Just("a"), Just("b"), Just(":p"), Just("c")];
            (proptest::collection::vec(seg, 0..4), any::<bool>()).prop_map(|(v, wild)| {
                let mut p = String::new();
                let mut n = 0;
                for s in v {
                    p.push('/');
                    if s == ":p" {
                        p.push_str(&format!(":p{n}"));
                        n += 1;
                    } else {
                        p.push_str(s);
                    }
                }
                if wild {
                    p.push_str("/*w");
                }
                if p.is_empty() { "/".into() } else { p }
            })
        }

        proptest! {
            #[test]
            fn prop_lookup_is_sound_and_complete(
                patterns in proptest::collection::vec(pattern(), 1..16),
                path in proptest::collection::vec(prop_oneof![Just("a"), Just("b"), Just("c"), Just("d")], 0..6),
            ) {
                let mut t = Trie::default();
                let mut table: Vec<Vec<Part>> = Vec::new();
                for p in &patterns {
                    let parts = parse(p).unwrap();
                    let ep = t.insert(&parts, table.len() as u32) as usize;
                    if ep == table.len() {
                        table.push(parts);
                    }
                }
                let path_str = format!("/{}", path.join("/"));
                let path_str = if path.is_empty() { "/".to_owned() } else { path_str };
                let found = t.find(&path_str);
                let any = table.iter().any(|parts| matches(parts, &path));
                match found {
                    Some((ep, caps)) => {
                        prop_assert!(matches(&table[ep as usize], &path), "{path_str} -> {patterns:?}");
                        for i in 0..MAX_PARAMS {
                            if let Some((s, e)) = caps.get(i) {
                                prop_assert!(s <= e && e <= path_str.len());
                            }
                        }
                    }
                    None => prop_assert!(!any, "{path_str} matches a pattern of {patterns:?}"),
                }
            }
        }
    }

    #[test]
    fn test_pattern_errors() {
        assert_eq!(parse("x"), Err(PatternError::NotAbsolute));
        assert_eq!(parse("/a//b"), Err(PatternError::Empty));
        assert_eq!(parse("/a/../b"), Err(PatternError::Dot));
        assert_eq!(parse("/:"), Err(PatternError::NoName));
        assert_eq!(parse("/*a/b"), Err(PatternError::WildcardNotLast));
        assert_eq!(
            parse("/:a/:a"),
            Err(PatternError::DuplicateName("a".into()))
        );
        assert_eq!(
            parse("/:a/:b/:c/:d/:e/:f/:g/:h/:i"),
            Err(PatternError::TooManyParams)
        );
        assert_eq!(parse("/a/").unwrap(), parse("/a").unwrap());
    }
}
