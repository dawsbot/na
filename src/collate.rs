//! `Intl.Collator('en').compare` for the ASCII strings npm sorts (package
//! names, lockfile locations, advisory ids). npm sorts with
//! `@isaacs/string-locale-compare`, which is ICU root collation: punctuation
//! and symbols carry primary weights (non-ignorable), digits follow them,
//! letters compare case-insensitively at the primary level and lowercase
//! sorts before uppercase at the tertiary level.

use std::cmp::Ordering;
use std::sync::LazyLock;

/// Printable ASCII in ICU root collation order, as produced by
/// `[...chars].sort(new Intl.Collator('en').compare)` in Node.
const ORDER: &str = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ";

struct Weights {
    primary: [u16; 128],
    tertiary: [u8; 128],
}

static WEIGHTS: LazyLock<Weights> = LazyLock::new(|| {
    let mut w = Weights { primary: [0; 128], tertiary: [0; 128] };
    let mut next: u16 = 1;
    for ch in ORDER.chars() {
        let i = ch as usize;
        if ch.is_ascii_uppercase() {
            // shares the primary weight of its lowercase form
            w.primary[i] = w.primary[ch.to_ascii_lowercase() as usize];
            w.tertiary[i] = 1;
        } else {
            w.primary[i] = next;
            next += 1;
        }
    }
    // control characters: ignorable in ICU; give them the lowest weight
    w
});

fn primary(c: char) -> u32 {
    let i = c as u32;
    if i < 128 {
        WEIGHTS.primary[i as usize] as u32
    } else {
        // Approximation for non-ASCII: after everything else, by code point.
        1000 + i
    }
}

fn tertiary(c: char) -> u8 {
    let i = c as u32;
    if i < 128 {
        WEIGHTS.tertiary[i as usize]
    } else {
        0
    }
}

pub fn compare(a: &str, b: &str) -> Ordering {
    // primary level over the whole string
    let mut ai = a.chars();
    let mut bi = b.chars();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => break,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let (px, py) = (primary(x), primary(y));
                if px != py {
                    return px.cmp(&py);
                }
            }
        }
    }
    // tertiary level (case)
    for (x, y) in a.chars().zip(b.chars()) {
        let (tx, ty) = (tertiary(x), tertiary(y));
        if tx != ty {
            return tx.cmp(&ty);
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_icu_samples() {
        let mut v = vec![
            "a", "A", "b", "B", "ab", "aB", "Ab", "AB", "a-b", "a_b", "a.b", "a/b", "a@b", "a1",
            "a-", "a_",
        ];
        v.sort_by(|x, y| compare(x, y));
        assert_eq!(
            v.join(" | "),
            "a | A | a_ | a_b | a- | a-b | a.b | a@b | a/b | a1 | ab | aB | Ab | AB | b | B"
        );
        assert_eq!(compare("Zebra", "apple"), Ordering::Greater);
        assert_eq!(compare("@a", "1"), Ordering::Less);
        assert_eq!(compare("node_modules/a", "node_modules/@a"), Ordering::Greater);
        assert_eq!(compare("a b", "ab"), Ordering::Less);
    }
}
