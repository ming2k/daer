// SPDX-License-Identifier: AGPL-3.0-only

//! Minimal protobuf wire-format reader.
//!
//! geodata files are protobuf lists, and only a handful of fields matter, so a
//! small reader is preferable to generated code: it can skip the entries we do
//! not need without allocating, which is the point of v2ray's
//! "memconservative" layout.

use crate::error::GeoDataError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    pub number: u32,
    pub value: FieldValue<'a>,
}

/// Reads a base-128 varint, rejecting over-long encodings.
pub fn read_varint(input: &[u8]) -> Result<(u64, &[u8]), GeoDataError> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (index, byte) in input.iter().enumerate() {
        if index >= 10 {
            return Err(GeoDataError::invalid("varint is longer than 10 bytes"));
        }
        let low = u64::from(byte & 0x7f);
        if shift >= 64 || (shift == 63 && low > 1) {
            return Err(GeoDataError::invalid("varint overflows 64 bits"));
        }
        value |= low << shift;
        if byte & 0x80 == 0 {
            return Ok((value, &input[index + 1..]));
        }
        shift += 7;
    }

    Err(GeoDataError::invalid("truncated varint"))
}

/// Reads one field and returns it with the remaining input.
pub fn next_field(input: &[u8]) -> Result<(Field<'_>, &[u8]), GeoDataError> {
    let (key, rest) = read_varint(input)?;
    let number = u32::try_from(key >> 3).map_err(|_| GeoDataError::invalid("field number"))?;
    if number == 0 {
        return Err(GeoDataError::invalid("field number 0"));
    }

    match key & 7 {
        0 => {
            let (value, rest) = read_varint(rest)?;
            Ok((
                Field {
                    number,
                    value: FieldValue::Varint(value),
                },
                rest,
            ))
        }
        1 => {
            let (_, rest) = take(rest, 8)?;
            Ok((
                Field {
                    number,
                    value: FieldValue::Fixed64,
                },
                rest,
            ))
        }
        2 => {
            let (length, rest) = read_varint(rest)?;
            let length = usize::try_from(length)
                .map_err(|_| GeoDataError::invalid("field length does not fit usize"))?;
            let (bytes, rest) = take(rest, length)?;
            Ok((
                Field {
                    number,
                    value: FieldValue::Bytes(bytes),
                },
                rest,
            ))
        }
        5 => {
            let (_, rest) = take(rest, 4)?;
            Ok((
                Field {
                    number,
                    value: FieldValue::Fixed32,
                },
                rest,
            ))
        }
        other => Err(GeoDataError::invalid_owned(format!(
            "unsupported wire type {other}"
        ))),
    }
}

fn take(input: &[u8], length: usize) -> Result<(&[u8], &[u8]), GeoDataError> {
    if input.len() < length {
        return Err(GeoDataError::invalid("truncated field"));
    }
    Ok(input.split_at(length))
}

/// Iterates over the fields of one message.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'a> {
    remaining: &'a [u8],
}

impl<'a> Fields<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<Field<'a>, GeoDataError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match next_field(self.remaining) {
            Ok((field, rest)) => {
                self.remaining = rest;
                Some(Ok(field))
            }
            Err(err) => {
                self.remaining = &[];
                Some(Err(err))
            }
        }
    }
}

pub fn string_field(value: &[u8]) -> Result<String, GeoDataError> {
    String::from_utf8(value.to_vec()).map_err(|_| GeoDataError::invalid("field is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_varints() {
        assert_eq!(read_varint(&[0x00]).unwrap().0, 0);
        assert_eq!(read_varint(&[0x7f]).unwrap().0, 127);
        assert_eq!(read_varint(&[0x80, 0x01]).unwrap().0, 128);
        assert_eq!(
            read_varint(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap().0,
            u32::MAX as u64
        );
        assert!(read_varint(&[0x80]).is_err());
        assert!(read_varint(&[0x80; 11]).is_err());
    }

    #[test]
    fn reads_length_delimited_fields() {
        // field 1, wire type 2, length 3, "abc"
        let (field, rest) = next_field(&[0x0a, 0x03, b'a', b'b', b'c']).unwrap();
        assert_eq!(field.number, 1);
        assert_eq!(field.value, FieldValue::Bytes(b"abc"));
        assert!(rest.is_empty());
    }

    #[test]
    fn skips_fixed_width_fields() {
        let (field, rest) = next_field(&[0x09, 1, 2, 3, 4, 5, 6, 7, 8, 0x00]).unwrap();
        assert_eq!(field.value, FieldValue::Fixed64);
        assert_eq!(rest, &[0x00]);
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(next_field(&[0x0a, 0x05, b'a']).is_err());
        assert!(next_field(&[0x0b]).is_err());
    }
}
