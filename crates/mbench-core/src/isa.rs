//! RISC-V ISA extension bitset and FDT `riscv,isa` / `riscv,isa-extensions` parsers.

use bitflags::bitflags;

bitflags! {
    /// Probed RISC-V ISA extensions relevant to S-mode benchmarking and conformance.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct IsaExtensions: u32 {
        const SSTC = 1 << 0;
        const H = 1 << 1;
        const SVADE = 1 << 2;
        const SVPBMT = 1 << 3;
        const ZICBOM = 1 << 4;
        const ZICNTR = 1 << 5;
        const ZIHPM = 1 << 6;
    }
}

impl IsaExtensions {
    /// Returns `true` if supervisor timer compare (`Sstc`) is present in the ISA bitset.
    pub const fn has_sstc(self) -> bool {
        self.contains(Self::SSTC)
    }

    /// Returns `true` if the hypervisor (`H`) extension is present in the ISA bitset.
    pub const fn has_h_ext(self) -> bool {
        self.contains(Self::H)
    }
}

struct ExtEntry {
    name: &'static str,
    flag: IsaExtensions,
}

const SINGLE_LETTER_EXTS: &[ExtEntry] = &[ExtEntry {
    name: "h",
    flag: IsaExtensions::H,
}];

const MULTI_LETTER_EXTS: &[ExtEntry] = &[
    ExtEntry {
        name: "sstc",
        flag: IsaExtensions::SSTC,
    },
    ExtEntry {
        name: "svade",
        flag: IsaExtensions::SVADE,
    },
    ExtEntry {
        name: "svpbmt",
        flag: IsaExtensions::SVPBMT,
    },
    ExtEntry {
        name: "zicbom",
        flag: IsaExtensions::ZICBOM,
    },
    ExtEntry {
        name: "zicntr",
        flag: IsaExtensions::ZICNTR,
    },
    ExtEntry {
        name: "zihpm",
        flag: IsaExtensions::ZIHPM,
    },
];

/// Parses a NUL-delimited `riscv,isa-extensions` FDT byte slice into an [`IsaExtensions`] bitset.
pub fn parse_isa_extensions_list(raw: &[u8]) -> IsaExtensions {
    let mut extensions = IsaExtensions::empty();
    for item in raw.split(|&b| b == 0) {
        if item.is_empty() {
            continue;
        }
        let Ok(name) = core::str::from_utf8(item) else {
            continue;
        };
        if !name.is_ascii() {
            continue;
        }
        let base_name = strip_trailing_version(name);
        if base_name.len() == 1 {
            if let Some(flag) = lookup_ext(SINGLE_LETTER_EXTS, base_name) {
                extensions |= flag;
            }
        } else if let Some(flag) = lookup_ext(MULTI_LETTER_EXTS, base_name) {
            extensions |= flag;
        }
    }
    extensions
}

/// Parses an underscore-delimited `riscv,isa` string (e.g. `rv64imafdch_zicntr_sstc`) into [`IsaExtensions`].
pub fn parse_isa_string(isa: &str) -> IsaExtensions {
    let trimmed = isa.trim_matches('\0').trim();
    if !trimmed.is_ascii() {
        return IsaExtensions::empty();
    }
    let rest = match trimmed.get(..4) {
        Some(prefix)
            if prefix.eq_ignore_ascii_case("rv64") || prefix.eq_ignore_ascii_case("rv32") =>
        {
            &trimmed[4..]
        }
        _ => trimmed,
    };
    if rest.is_empty() {
        return IsaExtensions::empty();
    }

    let mut extensions = IsaExtensions::empty();
    let mut parts = rest.split('_');
    if let Some(base_letters) = parts.next() {
        let bytes = base_letters.as_bytes();
        let mut idx = 0usize;
        while idx < bytes.len() {
            let b = bytes[idx];
            if b.is_ascii_digit() {
                while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                    idx += 1;
                }
                if idx < bytes.len()
                    && bytes[idx].eq_ignore_ascii_case(&b'p')
                    && bytes.get(idx + 1).is_some_and(u8::is_ascii_digit)
                {
                    idx += 1;
                    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                        idx += 1;
                    }
                }
                continue;
            }
            if let Ok(ch_str) = core::str::from_utf8(&bytes[idx..idx + 1])
                && let Some(flag) = lookup_ext(SINGLE_LETTER_EXTS, ch_str)
            {
                extensions |= flag;
            }
            idx += 1;
        }
    }

    for part in parts {
        if part.is_empty() {
            continue;
        }
        let base_name = strip_trailing_version(part);
        if base_name.len() == 1 {
            if let Some(flag) = lookup_ext(SINGLE_LETTER_EXTS, base_name) {
                extensions |= flag;
            }
        } else if let Some(flag) = lookup_ext(MULTI_LETTER_EXTS, base_name) {
            extensions |= flag;
        }
    }

    extensions
}

fn lookup_ext(table: &[ExtEntry], name: &str) -> Option<IsaExtensions> {
    table
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
        .map(|entry| entry.flag)
}

fn strip_trailing_version(name: &str) -> &str {
    let bytes = name.as_bytes();
    let mut end = bytes.len();
    if end == 0 || !bytes[end - 1].is_ascii_digit() {
        return name;
    }
    while end > 0 && bytes[end - 1].is_ascii_digit() {
        end -= 1;
    }
    if end == 0 || !bytes[end - 1].eq_ignore_ascii_case(&b'p') {
        return name;
    }
    let p_pos = end - 1;
    if p_pos == 0 || !bytes[p_pos - 1].is_ascii_digit() {
        return name;
    }
    let mut major_start = p_pos - 1;
    while major_start > 0 && bytes[major_start - 1].is_ascii_digit() {
        major_start -= 1;
    }
    if major_start == 0 {
        return name;
    }
    &name[..major_start]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_isa_extensions_list_and_intersects_safely() {
        assert_eq!(parse_isa_extensions_list(b""), IsaExtensions::empty());
        assert_eq!(
            parse_isa_extensions_list(b"i\0m\0a\0c\0h\0sstc\0zicntr\0unknown_ext\0"),
            IsaExtensions::H | IsaExtensions::SSTC | IsaExtensions::ZICNTR
        );
        let cpu0 = parse_isa_extensions_list(b"i\0h\0sstc\0svpbmt\0");
        let cpu1 = parse_isa_extensions_list(b"i\0sstc\0zicbom\0");
        let common = cpu0 & cpu1;
        assert!(common.has_sstc());
        assert!(!common.has_h_ext());
    }

    #[test]
    fn parses_versioned_and_unversioned_isa_strings() {
        assert_eq!(parse_isa_string(""), IsaExtensions::empty());
        let simple = parse_isa_string("rv64imafdch_zicntr_sstc_svade");
        assert!(simple.has_h_ext());
        assert!(simple.has_sstc());
        assert!(simple.contains(IsaExtensions::ZICNTR | IsaExtensions::SVADE));

        let versioned =
            parse_isa_string("rv64i2p1m2p0a2p1f2p2d2p2c2p0h1p0_zicsr2p0_sstc1p0_zve32x");
        assert!(versioned.has_h_ext());
        assert!(versioned.has_sstc());

        let svpbmt_only = parse_isa_string("RV64IMAFDC_SVPBMT");
        assert!(!svpbmt_only.has_h_ext());
        assert!(svpbmt_only.contains(IsaExtensions::SVPBMT));
    }

    #[test]
    fn rejects_non_ascii_isa_inputs_without_panicking() {
        assert_eq!(parse_isa_string("rv6é"), IsaExtensions::empty());
        assert_eq!(parse_isa_string("rv64_é_sstc"), IsaExtensions::empty());
        assert_eq!(
            parse_isa_extensions_list(b"i\0\xc3\xa9\0sstc\0"),
            IsaExtensions::SSTC
        );
    }
}
