//! Reading tar headers: blocks, checksums, numbers and the pax records that
//! carry long names.
use anyhow::{bail, Result};
use std::io::Read;

/// Every tar record is this many bytes.
pub(super) const BLOCK: usize = 512;

pub(super) fn read_block<R: Read>(reader: &mut R) -> Result<Option<[u8; BLOCK]>> {
    let mut block = [0u8; BLOCK];
    let mut filled = 0usize;
    while filled < BLOCK {
        let read = reader.read(&mut block[filled..])?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            bail!("archive ends in the middle of a header block");
        }
        filled += read;
    }
    Ok(Some(block))
}

pub(super) fn verify_checksum(header: &[u8; BLOCK]) -> Result<()> {
    let expected = parse_number(&header[148..156])?;
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        let value = if (148..156).contains(&index) {
            b' '
        } else {
            *byte
        };
        sum += value as u64;
    }
    if sum != expected {
        bail!("archive header checksum mismatch: expected {expected}, computed {sum}");
    }
    Ok(())
}

pub(super) fn parse_number(field: &[u8]) -> Result<u64> {
    // Base-256 marks a large value; the marker sits in the high bit and the
    // following bit is the sign.
    if field.first().map(|byte| byte & 0x80 != 0).unwrap_or(false) {
        if field[0] & 0x40 != 0 {
            bail!("archive number is negative, which this reader does not support");
        }
        let mut value: u64 = (field[0] & 0x3f) as u64;
        for byte in &field[1..] {
            value = value
                .checked_mul(256)
                .and_then(|shifted| shifted.checked_add(*byte as u64))
                .ok_or_else(|| anyhow::anyhow!("archive number does not fit in 64 bits"))?;
        }
        return Ok(value);
    }
    let text = String::from_utf8_lossy(field);
    let trimmed = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if trimmed.is_empty() {
        return Ok(0);
    }
    Ok(u64::from_str_radix(trimmed, 8)?)
}

/// A name field. Bytes that are not UTF-8 are refused.
pub(super) fn c_string(field: &[u8]) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    std::str::from_utf8(&field[..end])
        .map(|text| text.to_string())
        .map_err(|_| anyhow::anyhow!("archive member name is not valid UTF-8"))
}

pub(super) fn header_name(header: &[u8; BLOCK]) -> Result<String> {
    let name = c_string(&header[0..100])?;
    // Only a POSIX header carries the prefix field at 345..500.
    let posix = &header[257..263] == b"ustar\0" && &header[263..265] == b"00";
    if !posix {
        return Ok(name);
    }
    let prefix = c_string(&header[345..500])?;
    Ok(if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    })
}

/// A long name or a pax header is metadata, not payload; anything larger is a
/// sign the archive is not to be trusted.
pub(super) const MAX_METADATA: u64 = 1024 * 1024;
pub(super) const MAX_METADATA_TOTAL: u64 = 16 * 1024 * 1024;

/// An archive of a source tree or a binary package stays well under these.
pub(super) const MAX_MEMBERS: usize = 200_000;
/// Upper bound on the path components the unpacker will create.
pub(super) const MAX_PATH_COMPONENTS: usize = 2_000_000;
/// Extended headers count against this too; a header is never smaller than a
/// block.
pub(super) const MAX_HEADERS: usize = MAX_MEMBERS;
pub(crate) const MAX_UNPACKED_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The unpacking ceiling, overridable for hosts that build larger payloads.
pub(crate) fn max_unpacked_bytes() -> u64 {
    std::env::var("PORTALIS_MAX_UNPACKED")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MAX_UNPACKED_BYTES)
}

pub(super) fn read_body<R: Read>(reader: &mut R, size: u64) -> Result<Vec<u8>> {
    if size > MAX_METADATA {
        bail!("archive metadata block of {size} bytes exceeds the {MAX_METADATA} byte limit");
    }
    let mut body = vec![0u8; size as usize];
    reader.read_exact(&mut body)?;
    skip_bytes(reader, padding(size))?;
    Ok(body)
}

pub(super) fn read_text<R: Read>(reader: &mut R, size: u64) -> Result<String> {
    let body = read_body(reader, size)?;
    let text = std::str::from_utf8(&body)
        .map_err(|_| anyhow::anyhow!("archive metadata is not valid UTF-8"))?;
    Ok(text.trim_end_matches('\0').to_string())
}

pub(super) fn skip_bytes<R: Read>(reader: &mut R, count: u64) -> Result<()> {
    let mut left = count;
    let mut scratch = [0u8; 8192];
    while left > 0 {
        let want = left.min(scratch.len() as u64) as usize;
        reader.read_exact(&mut scratch[..want])?;
        left -= want as u64;
    }
    Ok(())
}

pub(super) fn padding(size: u64) -> u64 {
    let remainder = size % BLOCK as u64;
    if remainder == 0 {
        0
    } else {
        BLOCK as u64 - remainder
    }
}

/// Reads one `key=value` pair out of a pax extended header body.
pub(super) fn pax_records(body: &[u8]) -> Result<Vec<(String, String)>> {
    let bytes = body;
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        // a record is `<length> <key>=<value>\n`; the length counts the record
        let Some(space) = bytes[offset..].iter().position(|byte| *byte == b' ') else {
            bail!("pax record has no length field");
        };
        let space = offset + space;
        let length: usize = std::str::from_utf8(&bytes[offset..space])
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("pax record has a non-numeric length"))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("pax record length is out of range"))?;
        if length == 0 || space >= end || end > bytes.len() {
            bail!("pax record length is out of range");
        }
        let record = &bytes[space + 1..end];
        let record = record.strip_suffix(&b"\n"[..]).unwrap_or(record);
        let Some(equals) = record.iter().position(|byte| *byte == b'=') else {
            bail!("pax record holds no value");
        };
        let (name, value) = record.split_at(equals);
        let value = &value[1..];
        if name.is_empty() {
            bail!("pax record holds an empty key");
        }
        let name = String::from_utf8(name.to_vec())
            .map_err(|_| anyhow::anyhow!("pax record key is not valid UTF-8"))?;
        let value = String::from_utf8(value.to_vec())
            .map_err(|_| anyhow::anyhow!("pax record value is not valid UTF-8"))?;
        records.push((name, value));
        offset += length;
    }
    Ok(records)
}
