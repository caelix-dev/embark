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
///
/// Matching is a table over pattern position and name position, filled
/// from the end, so it costs pattern length times name length however the
/// wildcards are arranged. A backtracking matcher takes exponential time
/// on a run of them, and this one runs at build time on whatever pattern a
/// developer wrote.
pub(crate) fn matches(pattern: &str, name: &str) -> bool {
    let tokens = tokenize(pattern);
    let name: Vec<char> = name.chars().collect();

    // `next[j]`: does the pattern after the current token match `name[j..]`.
    // `here[j]`: the same for the pattern from the current token on.
    let mut next = vec![false; name.len() + 1];
    next[name.len()] = true;
    let mut here = vec![false; name.len() + 1];

    for token in tokens.iter().rev() {
        // Whether some `/` at or after `j` lets `**/` resume there.
        let mut segment_from_later = false;
        for j in (0..=name.len()).rev() {
            let c = name.get(j).copied();
            here[j] = match token {
                Token::Literal(want) => c == Some(*want) && next[j + 1],
                Token::One => c.is_some_and(|c| c != '/') && next[j + 1],
                // Any run of characters inside one segment.
                Token::Star => next[j] || (c.is_some_and(|c| c != '/') && here[j + 1]),
                // Any run at all, `/` included.
                Token::Cross => next[j] || (c.is_some() && here[j + 1]),
                // Any number of whole segments, zero among them: either the
                // rest matches from here, or it matches from just after
                // some later `/`.
                Token::Segments => next[j] || segment_from_later,
            };
            if c == Some('/') {
                segment_from_later |= here[j + 1];
            }
        }
        core::mem::swap(&mut here, &mut next);
    }
    next[0]
}

enum Token {
    Literal(char),
    /// `?`
    One,
    /// `*`
    Star,
    /// `**` somewhere other than as a whole segment.
    Cross,
    /// `**/`
    Segments,
}

fn tokenize(pattern: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        tokens.push(match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    Token::Segments
                } else {
                    Token::Cross
                }
            }
            '*' => Token::Star,
            '?' => Token::One,
            c => Token::Literal(c),
        });
    }
    tokens
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

    // A character, not a byte: `é` is two bytes, `日` three and `😀` four,
    // and each is one `?`.
    #[test]
    fn a_question_mark_is_one_character_in_any_script() {
        assert!(matches("?.png", "é.png"));
        assert!(matches("?.png", "日.png"));
        assert!(matches("?.png", "😀.png"));
        assert!(!matches("??.png", "é.png"));
        assert!(matches("caf?.txt", "café.txt"));
        assert!(matches("*é.txt", "café.txt"));
        assert!(matches("caf*", "café.txt"));
        assert!(matches("**/?.png", "sub/日.png"));
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

    // The fuzzer's first find: a run of stars against a name that does not
    // match sent the old backtracking matcher into exponential time. This
    // has to come back, false, in well under a second.
    #[test]
    fn a_run_of_wildcards_does_not_take_exponential_time() {
        let pattern = "*".repeat(40) + "x";
        let name = "a".repeat(60);
        assert!(!matches(&pattern, &name));
        let pattern = "**/".repeat(20) + "?*x";
        let name = "a/".repeat(30) + "b";
        assert!(!matches(&pattern, &name));
        assert!(matches(&("*".repeat(40) + "x"), &("a".repeat(60) + "x")));
    }

    #[test]
    fn a_pattern_matches_nothing_it_does_not_cover() {
        assert!(!matches("", "a"));
        assert!(matches("", ""));
        assert!(!matches("a.txt", "a.txtx"));
        assert!(!matches("a.txt", "xa.txt"));
    }
}
