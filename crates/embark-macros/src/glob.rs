//! The glob dialect `include` and `exclude` are written in.
//!
//! Small on purpose: patterns are matched against a path relative to the
//! embedded folder, always with `/` separators, and there is no filesystem
//! underneath by the time this runs. That leaves three constructs, and they
//! mean what they mean everywhere else -- in `.gitignore`, in shell globs,
//! in every other crate that filters a folder.

/// Whether `pattern` matches `name`, a `/`-separated relative path.
///
/// - `?` matches one character other than `/`.
/// - `*` matches any run of characters other than `/`, so it stays inside
///   one path segment.
/// - `**` crosses `/`. As a whole segment it stands for any number of
///   segments, so `**/*.png` finds a `.png` at any depth, `a/**/b` matches
///   `a/b` as well as `a/x/y/b`, and `a/**` matches everything under `a`.
///   Elsewhere it is simply a `*` that may cross `/`.
pub(crate) fn matches(pattern: &str, name: &str) -> bool {
    fn rec(p: &[u8], n: &[u8]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some(b'*') if p.get(1) == Some(&b'*') => {
                let rest = &p[2..];
                match rest.first() {
                    // A trailing `**` takes whatever is left, `/` included.
                    None => true,
                    // `**/` stands for any number of whole segments, zero
                    // among them: that is what lets `**/x` match a top-level
                    // `x` as well as `a/b/x`.
                    Some(b'/') => {
                        if rec(&rest[1..], n) {
                            return true;
                        }
                        n.iter()
                            .enumerate()
                            .any(|(at, &c)| c == b'/' && rec(p, &n[at + 1..]))
                    }
                    // `**` against anything else is a `*` that may cross `/`.
                    _ => rec(rest, n) || (!n.is_empty() && rec(p, &n[1..])),
                }
            }
            Some(b'*') => rec(&p[1..], n) || (!n.is_empty() && n[0] != b'/' && rec(p, &n[1..])),
            Some(b'?') => !n.is_empty() && n[0] != b'/' && rec(&p[1..], &n[1..]),
            Some(&c) => !n.is_empty() && n[0] == c && rec(&p[1..], &n[1..]),
        }
    }
    rec(pattern.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn a_single_star_stays_inside_one_segment() {
        assert!(matches("*.png", "logo.png"));
        assert!(!matches("*.png", "sub/logo.png"));
        assert!(matches("sub/*.png", "sub/logo.png"));
        assert!(!matches("sub/*.png", "sub/deep/logo.png"));
    }

    #[test]
    fn a_question_mark_is_one_character_and_never_a_separator() {
        assert!(matches("a?c.txt", "abc.txt"));
        assert!(!matches("a?c.txt", "ac.txt"));
        assert!(!matches("a?c", "a/c"));
    }

    #[test]
    fn a_double_star_segment_stands_for_any_number_of_segments() {
        // Zero of them included, which is the case a `*` cannot express and
        // the reason `**/x` is the idiom for "an x anywhere".
        assert!(matches("**/logo.png", "logo.png"));
        assert!(matches("**/logo.png", "sub/logo.png"));
        assert!(matches("**/logo.png", "a/b/c/logo.png"));
        assert!(matches("**/*.png", "a/b/logo.png"));
        assert!(!matches("**/*.png", "a/b/logo.jpg"));
    }

    #[test]
    fn a_double_star_matches_in_the_middle_and_at_the_end() {
        assert!(matches("a/**/b.txt", "a/b.txt"));
        assert!(matches("a/**/b.txt", "a/x/b.txt"));
        assert!(matches("a/**/b.txt", "a/x/y/b.txt"));
        assert!(!matches("a/**/b.txt", "z/x/b.txt"));

        assert!(matches("a/**", "a/b.txt"));
        assert!(matches("a/**", "a/x/y/b.txt"));
        // Everything *under* `a`, not a file named `a`.
        assert!(!matches("a/**", "a"));
    }

    #[test]
    fn a_bare_double_star_takes_everything() {
        assert!(matches("**", "a.txt"));
        assert!(matches("**", "a/b/c.txt"));
    }

    #[test]
    fn a_double_star_not_on_a_segment_boundary_is_a_star_that_crosses() {
        assert!(matches("a**z", "abz"));
        assert!(matches("a**z", "ab/cz"));
        // Whereas a single one does not.
        assert!(!matches("a*z", "ab/cz"));
    }

    #[test]
    fn a_pattern_matches_nothing_it_does_not_cover() {
        assert!(!matches("", "a"));
        assert!(matches("", ""));
        assert!(!matches("a.txt", "a.txtx"));
        assert!(!matches("a.txt", "xa.txt"));
    }
}
