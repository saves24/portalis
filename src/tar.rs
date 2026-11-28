//! Reading and unpacking tar archives without running `tar`.
//!
//! The build unpacks every archive through this module: a decompressor chosen by
//! the first bytes writes the stream, and the members are created here through
//! directory handles that never follow a symlink.

use anyhow::{bail, Result};
use std::io::{Read, Write};

mod extract;
mod parse;
pub use extract::{extract, extract_without_times};

pub(crate) use parse::max_unpacked_bytes;
use parse::{
    c_string, header_name, padding, parse_number, pax_records, read_block, read_body, read_text,
    skip_bytes, verify_checksum, MAX_HEADERS, MAX_METADATA_TOTAL,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    HardLink,
    /// A member that has no place in a source archive: device, fifo, socket, or
    /// a type this reader does not know.
    Unsupported(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    pub mode: u32,
    /// Group id the header records, `None` when the field cannot be read.
    pub gid: Option<u32>,
    /// Group name the header records, `None` when the field is empty.
    pub gname: Option<String>,
    pub mtime: i64,
    pub link_target: Option<String>,
}

/// Walks the headers, leaving the member data for the caller to consume.
struct Cursor<R: Read> {
    reader: R,
    long_name: Option<String>,
    long_link: Option<String>,
    pax_path: Option<String>,
    pax_link: Option<String>,
    pax_size: Option<u64>,
    pax_mtime: Option<i64>,
    metadata: u64,
    headers: usize,
}

impl<R: Read> Cursor<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            long_name: None,
            long_link: None,
            pax_path: None,
            pax_link: None,
            pax_size: None,
            pax_mtime: None,
            metadata: 0,
            headers: 0,
        }
    }

    /// Counts every block header, extended ones included, against `MAX_HEADERS`.
    fn count_header(&mut self) -> Result<()> {
        self.headers += 1;
        if self.headers > MAX_HEADERS {
            bail!("archive holds more than {MAX_HEADERS} headers");
        }
        Ok(())
    }

    /// Adds a metadata block's size to the `MAX_METADATA_TOTAL` budget.
    fn count_metadata(&mut self, size: u64) -> Result<()> {
        self.metadata = self.metadata.saturating_add(size);
        if self.metadata > MAX_METADATA_TOTAL {
            bail!("archive carries more than {MAX_METADATA_TOTAL} bytes of metadata");
        }
        Ok(())
    }

    /// Consumes an extended header, answering whether it was one.
    fn consume_metadata(&mut self, typeflag: char, size: u64) -> Result<bool> {
        match typeflag {
            'L' => {
                self.long_name = Some(read_text(&mut self.reader, size)?);
            }
            'K' => {
                self.long_link = Some(read_text(&mut self.reader, size)?);
            }
            'x' => {
                let body = read_body(&mut self.reader, size)?;
                let records = pax_records(&body)?;
                // Sparse members describe holes this reader does not rebuild.
                if records
                    .iter()
                    .any(|(name, _)| name.starts_with("GNU.sparse."))
                {
                    bail!("archive uses GNU sparse metadata, which this reader does not support");
                }
                for (name, value) in records {
                    match name.as_str() {
                        "path" => self.pax_path = Some(value),
                        "linkpath" => self.pax_link = Some(value),
                        // The extended header overrides the block header.
                        "size" => {
                            let declared = value.trim().parse::<u64>().ok();
                            if let Some(size) = declared {
                                let ceiling = max_unpacked_bytes();
                                if size > ceiling {
                                    bail!(
                                        "archive declares a {size} byte member, past the \
                                         {ceiling} byte limit"
                                    );
                                }
                            }
                            self.pax_size = declared;
                        }
                        "mtime" => {
                            self.pax_mtime = value
                                .split('.')
                                .next()
                                .and_then(|part| part.parse::<i64>().ok())
                        }
                        _ => {}
                    }
                }
            }
            'g' => {
                // A global header applies to every member after it; this reader
                // acts on per-member keys only.
                let body = read_body(&mut self.reader, size)?;
                for (name, _) in pax_records(&body)? {
                    if matches!(name.as_str(), "path" | "linkpath")
                        || name.starts_with("GNU.sparse.")
                    {
                        bail!(
                            "archive sets {name} in a global pax header, \
                             which this reader does not support"
                        );
                    }
                }
            }
            _ => return Ok(false),
        }
        self.count_metadata(size)?;
        Ok(true)
    }

    /// Builds the member the current header describes.
    fn build_member(
        &mut self,
        header: &[u8; 512],
        typeflag: char,
        size: u64,
        mode: u32,
    ) -> Result<Member> {
        let path = match self.pax_path.take() {
            Some(path) => path,
            None => match self.long_name.take() {
                Some(name) => name,
                None => header_name(header)?,
            },
        };
        // a name that was not taken above belongs to no member
        self.long_name = None;
        let kind = match typeflag {
            '0' | '\0' | '7' => Kind::File,
            '5' => Kind::Directory,
            '2' => Kind::Symlink,
            '1' => Kind::HardLink,
            other => Kind::Unsupported(other),
        };
        let link_target = match kind {
            Kind::Symlink | Kind::HardLink => Some(match self.pax_link.take() {
                Some(link) => link,
                None => match self.long_link.take() {
                    Some(link) => link,
                    None => c_string(&header[157..257])?,
                },
            }),
            _ => None,
        };
        self.long_link = None;
        self.pax_link = None;
        let mtime = self
            .pax_mtime
            .take()
            .unwrap_or_else(|| parse_number(&header[136..148]).unwrap_or(0) as i64);
        let size = self.pax_size.take().unwrap_or(size);
        Ok(Member {
            path,
            kind,
            size,
            mode,
            gid: parse_number(&header[116..124])
                .ok()
                .and_then(|value| u32::try_from(value).ok()),
            gname: c_string(&header[297..329])
                .ok()
                .filter(|name| !name.is_empty()),
            mtime,
            link_target,
        })
    }

    /// Returns the next member, or `None` at the end of the archive.
    fn next(&mut self) -> Result<Option<Member>> {
        loop {
            let Some(header) = read_block(&mut self.reader)? else {
                bail!("archive ends without an end-of-archive marker");
            };
            if header.iter().all(|byte| *byte == 0) {
                // The archive ends with two zero blocks.
                match read_block(&mut self.reader)? {
                    None => anyhow::bail!("archive ends after one zero block"),
                    Some(second) if second.iter().all(|byte| *byte == 0) => return Ok(None),
                    Some(_) => anyhow::bail!("data after the end-of-archive marker"),
                }
            }
            self.count_header()?;
            verify_checksum(&header)?;

            let typeflag = header[156] as char;
            let size = parse_number(&header[124..136])?;
            let mode = u32::try_from(parse_number(&header[100..108])?)
                .map_err(|_| anyhow::anyhow!("archive member mode does not fit in 32 bits"))?;

            if self.consume_metadata(typeflag, size)? {
                continue;
            }
            return self.build_member(&header, typeflag, size, mode).map(Some);
        }
    }

    fn copy_data<W: Write>(&mut self, size: u64, out: &mut W) -> Result<()> {
        let mut left = size;
        let mut buffer = [0u8; 8192];
        while left > 0 {
            let want = left.min(buffer.len() as u64) as usize;
            self.reader.read_exact(&mut buffer[..want])?;
            out.write_all(&buffer[..want])?;
            left -= want as u64;
        }
        skip_bytes(&mut self.reader, padding(size))
    }

    fn skip_data(&mut self, size: u64) -> Result<()> {
        skip_bytes(&mut self.reader, size)?;
        skip_bytes(&mut self.reader, padding(size))
    }
}

/// Reads the first regular member whose path equals `want`, without unpacking
/// anything else. Used to read a package's metadata before installing it.
pub fn read_member<R: Read>(reader: &mut R, want: &str) -> Result<Option<Vec<u8>>> {
    let mut cursor = Cursor::new(reader);
    while let Some(member) = cursor.next()? {
        let path = member
            .path
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        if member.kind == Kind::File && path == want {
            // A header may claim any size; metadata files are small.
            const MAX_MEMBER_BYTES: u64 = 8 * 1024 * 1024;
            if member.size > MAX_MEMBER_BYTES {
                bail!(
                    "member {path} claims {} bytes; metadata that large is refused",
                    member.size
                );
            }
            let mut data = vec![0u8; member.size as usize];
            cursor.reader.read_exact(&mut data)?;
            skip_bytes(&mut cursor.reader, padding(member.size))?;
            return Ok(Some(data));
        }
        if member.size > 0 {
            cursor.skip_data(member.size)?;
        }
    }
    Ok(None)
}

/// Reads every header in the archive, skipping file contents. Used to inspect
/// member modes before an import is accepted.
pub fn members<R: Read>(reader: &mut R) -> Result<Vec<Member>> {
    let mut cursor = Cursor::new(reader);
    let mut found = Vec::new();
    while let Some(member) = cursor.next()? {
        if member.size > 0 {
            cursor.skip_data(member.size)?;
        }
        found.push(member);
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
