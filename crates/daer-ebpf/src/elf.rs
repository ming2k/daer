// SPDX-License-Identifier: AGPL-3.0-only

//! ELF section-name normalization for the shared datapath object.
//!
//! # Why this exists
//!
//! `control/kern/tproxy.c` is not ours to edit: it is compiled by upstream's
//! build and, in the Go implementation, loaded by `ebpf-go`. Its programs are
//! declared with section names that `ebpf-go` accepts and `aya` does not:
//!
//! | Upstream section | aya accepts | Meaning |
//! | --- | --- | --- |
//! | `tc/<name>` | `classifier/<name>` | tc classifier |
//! | `sk_skb/<name>` | `sk_skb/stream_verdict` | sockmap stream verdict |
//!
//! `aya-obj`'s `ProgramSection::from_str` is strict: it only knows `classifier`,
//! and for `sk_skb` only the two fixed suffixes. Rather than fork a 4,400-line C
//! datapath or patch upstream's object at build time, the loader adapts the
//! object it is given. That keeps the ABI a *contract with the shared source*
//! instead of a build-time fork, and it means an object built by either project
//! loads.
//!
//! `sk_skb/<anything>` maps to `sk_skb/stream_verdict` because that is how the Go
//! implementation attaches it (`AttachSkSKBStreamVerdict` in
//! `control/control_plane_core_bind.go`); `tcp_offload_redirect` is the only such
//! program.
//!
//! Nothing else is rewritten: an unknown section stays as it is, so a genuinely
//! unsupported program still fails loudly in `aya`.

use std::borrow::Cow;

/// A malformed or unsupported ELF object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    NotElf,
    Truncated {
        what: &'static str,
    },
    /// Extended section numbering (`e_shnum == 0`) is not used by any object we
    /// load, and handling it would need the section-0 fallback path.
    Unsupported {
        what: &'static str,
    },
    /// A renamed string table does not fit the ELF's address space.
    Overflow,
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotElf => f.write_str("not an ELF object"),
            Self::Truncated { what } => write!(f, "truncated ELF: {what}"),
            Self::Unsupported { what } => write!(f, "unsupported ELF: {what}"),
            Self::Overflow => f.write_str("renamed section table does not fit the object"),
        }
    }
}

impl std::error::Error for ElfError {}

const SHN_XINDEX: u16 = 0xffff;

/// Rewrites section names so that `aya` accepts the shared datapath object.
///
/// Returns the input untouched ([`Cow::Borrowed`]) when no section needs
/// rewriting, which is the case for an object that was already normalized.
///
/// # Errors
///
/// Returns [`ElfError`] when the object is not a 32/64-bit ELF or is truncated.
pub fn normalize_section_names(object: &[u8]) -> Result<Cow<'_, [u8]>, ElfError> {
    let elf = Elf::parse(object)?;
    let names = elf.section_names(object)?;

    let renamed: Vec<Option<String>> = names.iter().map(|name| map_section_name(name)).collect();
    if renamed.iter().all(Option::is_none) {
        return Ok(Cow::Borrowed(object));
    }

    // A renamed section is longer than the original, so it does not fit in
    // place. Two rewrites are possible: extend the existing `.shstrtab`, or add
    // a new one. Extending is not safe — clang emits one string blob that serves
    // as *both* the section-name table and the symbol-name table, so overwriting
    // it would break symbol resolution. Instead a fresh string table and a fresh
    // section header table are appended, and the ELF header is pointed at them;
    // every existing byte keeps its meaning.
    let mut table = Vec::new();
    let mut offsets = Vec::with_capacity(names.len() + 1);
    for (index, name) in names.iter().enumerate() {
        offsets.push(u32::try_from(table.len()).map_err(|_| ElfError::Overflow)?);
        table.extend_from_slice(renamed[index].as_deref().unwrap_or(name).as_bytes());
        table.push(0);
    }
    let strtab_name = u32::try_from(table.len()).map_err(|_| ElfError::Overflow)?;
    table.extend_from_slice(b".shstrtab\0");

    let entry = usize::from(elf.shentsize);
    let old_count = usize::from(elf.shnum);
    let new_count = u16::try_from(old_count + 1).map_err(|_| ElfError::Overflow)?;
    let old_table = usize::try_from(elf.shoff).map_err(|_| ElfError::Overflow)?;
    let old_table_end = old_table
        .checked_add(old_count * entry)
        .ok_or(ElfError::Overflow)?;
    let old_headers = object
        .get(old_table..old_table_end)
        .ok_or(ElfError::Truncated {
            what: "section header table",
        })?;

    let mut out = object.to_vec();
    let strtab_offset = out.len();
    out.extend_from_slice(&table);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }

    let header_table_offset = out.len();
    out.extend_from_slice(old_headers);
    for (index, offset) in offsets.iter().enumerate() {
        elf.write_u32(&mut out, header_table_offset + index * entry, *offset)?;
    }

    // The new string table needs its own section header so that `e_shstrndx`
    // names a real section.
    let new_section = header_table_offset + old_count * entry;
    out.resize(new_section + entry, 0);
    const SHT_STRTAB: u32 = 3;
    elf.write_u32(&mut out, new_section, strtab_name)?;
    elf.write_u32(&mut out, new_section + 4, SHT_STRTAB)?;
    elf.write_u64_at(&mut out, new_section + 0x18, strtab_offset as u64)?;
    elf.write_u64_at(&mut out, new_section + 0x20, table.len() as u64)?;
    elf.write_u64_at(&mut out, new_section + 0x30, 1)?;

    elf.write_u64_at(&mut out, elf.shoff_at, header_table_offset as u64)?;
    elf.write_u16(&mut out, elf.shnum_at, new_count)?;
    elf.write_u16(&mut out, elf.shstrndx_at, old_count as u16)?;

    Ok(Cow::Owned(out))
}

/// Maps an upstream section name onto the name `aya` expects, or `None` when it
/// is already accepted.
fn map_section_name(name: &str) -> Option<String> {
    if let Some(rest) = name.strip_prefix("tc/") {
        return Some(format!("classifier/{rest}"));
    }
    if let Some(rest) = name.strip_prefix("sk_skb/")
        && !matches!(rest, "stream_parser" | "stream_verdict")
    {
        return Some("sk_skb/stream_verdict".to_owned());
    }
    None
}

/// The handful of ELF header fields this module needs, in either class and
/// either endianness.
struct Elf {
    is_64: bool,
    big_endian: bool,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
    /// Offsets of the header fields this module rewrites.
    shoff_at: usize,
    shnum_at: usize,
    shstrndx_at: usize,
    /// Byte offsets of `sh_offset` and `sh_size` inside a section header.
    offset_field: usize,
    size_field: usize,
}

impl Elf {
    fn parse(object: &[u8]) -> Result<Self, ElfError> {
        if object.len() < 0x40 || &object[..4] != b"\x7fELF" {
            return Err(ElfError::NotElf);
        }
        let is_64 = match object[4] {
            1 => false,
            2 => true,
            _ => return Err(ElfError::NotElf),
        };
        let big_endian = match object[5] {
            1 => false,
            2 => true,
            _ => return Err(ElfError::NotElf),
        };
        let elf = Self {
            is_64,
            big_endian,
            shoff: 0,
            shentsize: 0,
            shnum: 0,
            shstrndx: 0,
            shoff_at: if is_64 { 0x28 } else { 0x20 },
            shnum_at: if is_64 { 0x3c } else { 0x30 },
            shstrndx_at: if is_64 { 0x3e } else { 0x32 },
            offset_field: if is_64 { 0x18 } else { 0x10 },
            size_field: if is_64 { 0x20 } else { 0x14 },
        };

        let (shoff_at, shentsize_at, shnum_at, shstrndx_at) = if is_64 {
            (0x28, 0x3a, 0x3c, 0x3e)
        } else {
            (0x20, 0x2e, 0x30, 0x32)
        };
        let shoff = if is_64 {
            elf.read_u64(object, shoff_at)?
        } else {
            u64::from(elf.read_u32(object, shoff_at)?)
        };
        let shentsize = elf.read_u16(object, shentsize_at)?;
        let shnum = elf.read_u16(object, shnum_at)?;
        let shstrndx = elf.read_u16(object, shstrndx_at)?;

        if shnum == 0 || shstrndx == SHN_XINDEX {
            return Err(ElfError::Unsupported {
                what: "extended section numbering",
            });
        }
        if shentsize == 0 {
            return Err(ElfError::Unsupported {
                what: "zero-sized section header entry",
            });
        }

        Ok(Self {
            shoff,
            shentsize,
            shnum,
            shstrndx,
            ..elf
        })
    }

    fn section_header_offset(&self, index: usize) -> Result<usize, ElfError> {
        if index >= usize::from(self.shnum) {
            return Err(ElfError::Truncated {
                what: "section index out of range",
            });
        }
        let base = usize::try_from(self.shoff)
            .map_err(|_| ElfError::Overflow)?
            .checked_add(index * usize::from(self.shentsize))
            .ok_or(ElfError::Overflow)?;
        Ok(base)
    }

    /// Every section name, in section-table order.
    fn section_names<'a>(&self, object: &'a [u8]) -> Result<Vec<&'a str>, ElfError> {
        let strtab = self.section_header_offset(usize::from(self.shstrndx))?;
        let offset = usize::try_from(self.read_u64_field(object, strtab + self.offset_field)?)
            .map_err(|_| ElfError::Overflow)?;
        let size = usize::try_from(self.read_u64_field(object, strtab + self.size_field)?)
            .map_err(|_| ElfError::Overflow)?;
        let table = object
            .get(offset..offset.checked_add(size).ok_or(ElfError::Overflow)?)
            .ok_or(ElfError::Truncated {
                what: "section name table",
            })?;

        let mut names = Vec::with_capacity(usize::from(self.shnum));
        for index in 0..usize::from(self.shnum) {
            let header = self.section_header_offset(index)?;
            let name_at = usize::try_from(self.read_u32_field(object, header)?)
                .map_err(|_| ElfError::Overflow)?;
            let rest = table.get(name_at..).ok_or(ElfError::Truncated {
                what: "section name offset",
            })?;
            let end = rest
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(ElfError::Truncated {
                    what: "unterminated section name",
                })?;
            names.push(
                std::str::from_utf8(&rest[..end]).map_err(|_| ElfError::Truncated {
                    what: "section name is not UTF-8",
                })?,
            );
        }
        Ok(names)
    }

    fn read_u16(&self, bytes: &[u8], at: usize) -> Result<u16, ElfError> {
        let raw = bytes
            .get(at..at + 2)
            .ok_or(ElfError::Truncated { what: "u16 field" })?;
        let raw = [raw[0], raw[1]];
        Ok(if self.big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    }

    fn read_u32(&self, bytes: &[u8], at: usize) -> Result<u32, ElfError> {
        let raw = bytes
            .get(at..at + 4)
            .ok_or(ElfError::Truncated { what: "u32 field" })?;
        let raw = [raw[0], raw[1], raw[2], raw[3]];
        Ok(if self.big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    }

    fn read_u64(&self, bytes: &[u8], at: usize) -> Result<u64, ElfError> {
        let raw = bytes
            .get(at..at + 8)
            .ok_or(ElfError::Truncated { what: "u64 field" })?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(raw);
        Ok(if self.big_endian {
            u64::from_be_bytes(buf)
        } else {
            u64::from_le_bytes(buf)
        })
    }

    fn read_u32_field(&self, bytes: &[u8], at: usize) -> Result<u64, ElfError> {
        self.read_u32(bytes, at).map(u64::from)
    }

    fn read_u64_field(&self, bytes: &[u8], at: usize) -> Result<u64, ElfError> {
        if self.is_64 {
            self.read_u64(bytes, at)
        } else {
            self.read_u32(bytes, at).map(u64::from)
        }
    }

    fn write_u16(&self, bytes: &mut [u8], at: usize, value: u16) -> Result<(), ElfError> {
        let slot = bytes
            .get_mut(at..at + 2)
            .ok_or(ElfError::Truncated { what: "u16 field" })?;
        slot.copy_from_slice(&if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
        Ok(())
    }

    fn write_u32(&self, bytes: &mut [u8], at: usize, value: u32) -> Result<(), ElfError> {
        let slot = bytes
            .get_mut(at..at + 4)
            .ok_or(ElfError::Truncated { what: "u32 field" })?;
        slot.copy_from_slice(&if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
        Ok(())
    }

    fn write_u64_at(&self, bytes: &mut [u8], at: usize, value: u64) -> Result<(), ElfError> {
        if self.is_64 {
            let slot = bytes
                .get_mut(at..at + 8)
                .ok_or(ElfError::Truncated { what: "u64 field" })?;
            slot.copy_from_slice(&if self.big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            });
        } else if let Ok(value) = u32::try_from(value) {
            self.write_u32(bytes, at, value)?;
        } else {
            return Err(ElfError::Overflow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal 64-bit little-endian ELF with `sections` and a string
    /// table, which is all this module ever looks at.
    fn synthetic(sections: &[&str]) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut offsets = Vec::new();
        for name in sections {
            offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        let shnum = sections.len() + 2; // NULL, our sections, then .shstrtab
        let strtab_index = shnum - 1;
        offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(b".shstrtab\0");

        let shoff = 0x40usize;
        let mut out = vec![0u8; shoff];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // 64-bit
        out[5] = 1; // little-endian
        out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&(shnum as u16).to_le_bytes());
        out[0x3e..0x40].copy_from_slice(&(strtab_index as u16).to_le_bytes());

        out.resize(shoff + shnum * 64, 0);
        let strtab_offset = out.len();
        out.extend_from_slice(&strtab);

        for index in 0..shnum {
            let base = shoff + index * 64;
            let name = if index == 0 { 0 } else { offsets[index - 1] };
            out[base..base + 4].copy_from_slice(&name.to_le_bytes());
            if index == strtab_index {
                out[base + 0x18..base + 0x20]
                    .copy_from_slice(&(strtab_offset as u64).to_le_bytes());
                out[base + 0x20..base + 0x28].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
            }
        }
        out
    }

    fn names_of(object: &[u8]) -> Vec<String> {
        let elf = Elf::parse(object).expect("parses");
        elf.section_names(object)
            .expect("names")
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    }

    #[test]
    fn rewrites_tc_and_sk_skb_sections() {
        let object = synthetic(&["tc/lan_egress_l2", "sk_skb/tcp_offload_redirect", "my_map"]);
        let normalized = normalize_section_names(&object).expect("normalizes");
        // The synthetic object already carries a `.shstrtab`; the rewrite appends
        // a second, complete one and points `e_shstrndx` at it.
        assert_eq!(
            names_of(&normalized),
            [
                "",
                "classifier/lan_egress_l2",
                "sk_skb/stream_verdict",
                "my_map",
                ".shstrtab",
                ".shstrtab"
            ]
        );
    }

    #[test]
    fn leaves_an_already_valid_object_alone() {
        let object = synthetic(&["classifier/lan_egress_l2", "sk_skb/stream_verdict", "xdp/y"]);
        let normalized = normalize_section_names(&object).expect("normalizes");
        assert!(matches!(normalized, Cow::Borrowed(_)));
    }

    #[test]
    fn keeps_valid_sk_skb_flavors() {
        let object = synthetic(&["sk_skb/stream_parser", "sk_skb/stream_verdict"]);
        assert!(matches!(
            normalize_section_names(&object).expect("normalizes"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(
            normalize_section_names(b"not an elf file at all").unwrap_err(),
            ElfError::NotElf
        );
    }
}
