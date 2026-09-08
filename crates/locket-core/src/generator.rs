//! Password and passphrase generation.
//!
//! All randomness comes from the OS via `getrandom`, and selection uses
//! rejection sampling rather than `% len`, which would bias the low-numbered
//! characters of any alphabet whose length is not a power of two.

use crate::{Error, Result, secret::SecretString};

pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";

/// Characters that are easy to confuse in a printed or dictated password.
const AMBIGUOUS: &[char] = &['0', 'O', 'o', '1', 'l', 'I', '5', 'S', '2', 'Z', '8', 'B'];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRecipe {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Drop visually confusable characters from the alphabet.
    pub exclude_ambiguous: bool,
}

impl Default for PasswordRecipe {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordRecipe {
    fn alphabets(&self) -> Vec<Vec<char>> {
        let mut sets = Vec::new();
        let mut push = |enabled: bool, src: &str| {
            if enabled {
                let chars: Vec<char> = src
                    .chars()
                    .filter(|c| !self.exclude_ambiguous || !AMBIGUOUS.contains(c))
                    .collect();
                if !chars.is_empty() {
                    sets.push(chars);
                }
            }
        };
        push(self.lowercase, LOWERCASE);
        push(self.uppercase, UPPERCASE);
        push(self.digits, DIGITS);
        push(self.symbols, SYMBOLS);
        sets
    }

    /// Shannon entropy of the generated password, in bits.
    pub fn entropy_bits(&self) -> f64 {
        let pool: usize = self.alphabets().iter().map(Vec::len).sum();
        if pool <= 1 || self.length == 0 {
            return 0.0;
        }
        (pool as f64).log2() * self.length as f64
    }
}

/// Generate a password matching `recipe`.
///
/// Guarantees at least one character from every enabled class, which is what
/// most "password must contain..." validators demand. The guaranteed
/// characters are placed by a random shuffle, not appended, so their positions
/// carry no information.
pub fn password(recipe: &PasswordRecipe) -> Result<SecretString> {
    let sets = recipe.alphabets();
    if sets.is_empty() {
        return Err(Error::Other(
            "at least one character class must be enabled".into(),
        ));
    }
    if recipe.length < sets.len() {
        return Err(Error::Other(format!(
            "length {} cannot cover {} required character classes",
            recipe.length,
            sets.len()
        )));
    }

    let pool: Vec<char> = sets.iter().flatten().copied().collect();
    let mut out: Vec<char> = Vec::with_capacity(recipe.length);

    // One from each class first, to satisfy composition rules...
    for set in &sets {
        out.push(*choose(set)?);
    }
    // ...then fill the remainder from the union.
    while out.len() < recipe.length {
        out.push(*choose(&pool)?);
    }

    shuffle(&mut out)?;
    Ok(SecretString::new(out.into_iter().collect::<String>()))
}

/// Generate a Diceware-style passphrase from `wordlist`.
pub fn passphrase(wordlist: &[&str], words: usize, separator: char) -> Result<SecretString> {
    if wordlist.is_empty() {
        return Err(Error::Other("wordlist is empty".into()));
    }
    let mut parts = Vec::with_capacity(words);
    for _ in 0..words {
        parts.push(*choose(wordlist)?);
    }
    Ok(SecretString::new(parts.join(&separator.to_string())))
}

/// Uniformly pick one element, without modulo bias.
fn choose<T>(items: &[T]) -> Result<&T> {
    Ok(&items[uniform_index(items.len())?])
}

/// A uniform index in `0..n`, by rejection sampling.
fn uniform_index(n: usize) -> Result<usize> {
    assert!(n > 0, "uniform_index requires a non-empty range");
    if n == 1 {
        return Ok(0);
    }
    // Largest multiple of n that fits in u64; values at or above it would make
    // the low residues more likely, so we draw again instead.
    let limit = u64::MAX - (u64::MAX % n as u64);
    loop {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)?;
        let v = u64::from_le_bytes(buf);
        if v < limit {
            return Ok((v % n as u64) as usize);
        }
    }
}

/// Fisher-Yates, using the same unbiased index source.
fn shuffle<T>(items: &mut [T]) -> Result<()> {
    for i in (1..items.len()).rev() {
        let j = uniform_index(i + 1)?;
        items.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn respects_length_and_classes() {
        let recipe = PasswordRecipe {
            length: 32,
            ..Default::default()
        };
        let pw = password(&recipe).unwrap();
        let s = pw.expose();
        assert_eq!(s.chars().count(), 32);
        assert!(s.chars().any(|c| LOWERCASE.contains(c)));
        assert!(s.chars().any(|c| UPPERCASE.contains(c)));
        assert!(s.chars().any(|c| DIGITS.contains(c)));
        assert!(s.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn honours_disabled_classes() {
        let recipe = PasswordRecipe {
            length: 24,
            symbols: false,
            uppercase: false,
            ..Default::default()
        };
        let pw = password(&recipe).unwrap();
        assert!(
            pw.expose()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn excludes_ambiguous_characters_when_asked() {
        let recipe = PasswordRecipe {
            length: 64,
            exclude_ambiguous: true,
            ..Default::default()
        };
        let pw = password(&recipe).unwrap();
        assert!(!pw.expose().chars().any(|c| AMBIGUOUS.contains(&c)));
    }

    #[test]
    fn rejects_impossible_recipes() {
        // Four classes cannot fit in three characters.
        assert!(
            password(&PasswordRecipe {
                length: 3,
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            password(&PasswordRecipe {
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: false,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn generated_passwords_are_distinct() {
        let recipe = PasswordRecipe::default();
        let set: HashSet<String> = (0..64)
            .map(|_| password(&recipe).unwrap().expose().to_owned())
            .collect();
        assert_eq!(set.len(), 64, "generator produced a collision");
    }

    #[test]
    fn required_characters_are_not_pinned_to_the_front() {
        // If the guaranteed picks were simply appended in class order, the
        // first character would always be lowercase.
        let recipe = PasswordRecipe {
            length: 8,
            ..Default::default()
        };
        let all_lower_first = (0..64).all(|_| {
            password(&recipe)
                .unwrap()
                .expose()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase())
        });
        assert!(
            !all_lower_first,
            "class order leaked into character positions"
        );
    }

    #[test]
    fn entropy_matches_hand_calculation() {
        let recipe = PasswordRecipe {
            length: 10,
            lowercase: true,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        // 26 + 10 = 36 symbols, 10 characters.
        let expected = 36f64.log2() * 10.0;
        assert!((recipe.entropy_bits() - expected).abs() < 1e-9);
    }

    #[test]
    fn passphrase_uses_the_wordlist() {
        let words = ["alpha", "bravo", "charlie", "delta"];
        let p = passphrase(&words, 5, '-').unwrap();
        let parts: Vec<&str> = p.expose().split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| words.contains(w)));
    }

    #[test]
    fn uniform_index_stays_in_range() {
        for n in 1..=17 {
            for _ in 0..64 {
                assert!(uniform_index(n).unwrap() < n);
            }
        }
    }
}
