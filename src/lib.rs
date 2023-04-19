//! CBOR decoder
use std::{
    fmt,
    io::{self, Read, Seek, SeekFrom},
    result,
};

/// Type alias for a blake3 hash
pub type Hash = [u8; 32];

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    /// Unexpected end of file
    UnexpectedEof,
    /// Unexpected code
    UnexpectedCode(u8),
    /// Unknown cbor tag
    UnknownTag(u8),
    /// Invalid cid prefix
    InvalidCidPrefix(u8),
    /// Invalid length
    LengthOutOfRange,
    /// Invalid varint
    InvalidVarint,
    /// Invalid cid version
    InvalidCidVersion,
    /// Invalid hash algorithm (not blake3)
    InvalidHashAlgorithm,
    /// Invalid hash length (not 32)
    InvalidHashLength,
    /// Generic io error
    IoError(io::Error),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::UnexpectedEof => ParseError::UnexpectedEof,
            _ => ParseError::IoError(e),
        }
    }
}

/// Reads a u8 from a byte stream.
fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut buf = [0; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// Reads a u16 from a byte stream.
fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Reads a u32 from a byte stream.
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Reads a u64 from a byte stream.
fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut buf = [0; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn parse_u64_varint(mut input: &[u8]) -> Result<(u64, &[u8]), ParseError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;

    loop {
        let byte = input[0];
        input = &input[1..];

        let bits = (byte & 0x7F) as u64;
        value |= bits << shift;

        if (byte & 0x80) == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(ParseError::InvalidVarint);
        }
    }

    Ok((value, input))
}

/// Reads `len` number of bytes from a byte stream.
fn read_bytes<R: Read>(r: &mut R, len: usize) -> result::Result<Vec<u8>, ParseError> {
    // Limit up-front allocations to 16KiB as the length is user controlled.
    let mut buf = Vec::with_capacity(len.min(16 * 1024));
    r.take(len as u64).read_to_end(&mut buf)?;
    if buf.len() != len {
        return Err(ParseError::UnexpectedEof);
    }
    Ok(buf)
}

/// Reads a cid from a stream of cbor encoded bytes.
fn read_link<R: Read>(r: &mut R) -> Result<(u64, Hash), ParseError> {
    let ty = read_u8(r)?;
    if ty != 0x58 {
        return Err(ParseError::UnknownTag(ty));
    }
    let len = read_u8(r)?;
    if len == 0 {
        return Err(ParseError::LengthOutOfRange);
    }
    let bytes = read_bytes(r, len as usize)?;
    if bytes[0] != 0 {
        return Err(ParseError::InvalidCidPrefix(bytes[0]));
    }

    if bytes.len() < 32 {
        return Err(ParseError::LengthOutOfRange);
    }
    // check that version is 1
    // skip the first byte per
    // https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-cbor.md#links
    let (version_header, rest) = bytes.split_at(2);
    if version_header != [0, 1] {
        return Err(ParseError::InvalidCidVersion);
    }
    let (codec, rest) = parse_u64_varint(rest)?;
    // check that hash code is 0x1e (blake3) and length is 32
    let (mh_header, rest) = rest.split_at(2);
    if mh_header != [0x1e, 0x20] {
        return Err(ParseError::InvalidHashAlgorithm);
    }
    if rest.len() != 32 {
        return Err(ParseError::InvalidHashLength);
    }
    let bytes = <[u8; 32]>::try_from(rest).unwrap();
    Ok((codec, bytes))
}

/// Reads the len given a base.
fn read_len<R: Read + Seek>(r: &mut R, major: u8) -> Result<usize, ParseError> {
    Ok(match major {
        0x00..=0x17 => major as usize,
        0x18 => read_u8(r)? as usize,
        0x19 => read_u16(r)? as usize,
        0x1a => read_u32(r)? as usize,
        0x1b => {
            let len = read_u64(r)?;
            if len > usize::max_value() as u64 {
                return Err(ParseError::LengthOutOfRange);
            }
            len as usize
        }
        major => return Err(ParseError::UnexpectedCode(major)),
    })
}

/// Read a dag-cbor block and extract all the links.
///
/// 'r' is a reader that is expected to be at the start of a dag-cbor block.
/// 'res' is a vector that will be populated with all the links found.
///
/// Will fail unless all links are blake3 hashes.
pub fn references<R: Read + Seek>(r: &mut R, res: &mut Vec<(u64, Hash)>) -> Result<(), ParseError> {
    let major = read_u8(r)?;
    match major {
        // Major type 0: an unsigned integer
        0x00..=0x17 => {}
        0x18 => {
            r.seek(SeekFrom::Current(1))?;
        }
        0x19 => {
            r.seek(SeekFrom::Current(2))?;
        }
        0x1a => {
            r.seek(SeekFrom::Current(4))?;
        }
        0x1b => {
            r.seek(SeekFrom::Current(8))?;
        }

        // Major type 1: a negative integer
        0x20..=0x37 => {}
        0x38 => {
            r.seek(SeekFrom::Current(1))?;
        }
        0x39 => {
            r.seek(SeekFrom::Current(2))?;
        }
        0x3a => {
            r.seek(SeekFrom::Current(4))?;
        }
        0x3b => {
            r.seek(SeekFrom::Current(8))?;
        }

        // Major type 2: a byte string
        0x40..=0x5b => {
            let len = read_len(r, major - 0x40)?;
            r.seek(SeekFrom::Current(len as _))?;
        }

        // Major type 3: a text string
        0x60..=0x7b => {
            let len = read_len(r, major - 0x60)?;
            r.seek(SeekFrom::Current(len as _))?;
        }

        // Major type 4: an array of data items
        0x80..=0x9b => {
            let len = read_len(r, major - 0x80)?;
            for _ in 0..len {
                references(r, res)?;
            }
        }

        // Major type 4: an array of data items (indefinite length)
        0x9f => loop {
            let major = read_u8(r)?;
            if major == 0xff {
                break;
            }
            r.seek(SeekFrom::Current(-1))?;
            references(r, res)?;
        },

        // Major type 5: a map of pairs of data items
        0xa0..=0xbb => {
            let len = read_len(r, major - 0xa0)?;
            for _ in 0..len {
                references(r, res)?;
                references(r, res)?;
            }
        }

        // Major type 5: a map of pairs of data items (indefinite length)
        0xbf => loop {
            let major = read_u8(r)?;
            if major == 0xff {
                break;
            }
            r.seek(SeekFrom::Current(-1))?;
            references(r, res)?;
            references(r, res)?;
        },

        // Major type 6: optional semantic tagging of other major types
        0xd8 => {
            let tag = read_u8(r)?;
            if tag == 42 {
                res.push(read_link(r)?);
            } else {
                references(r, res)?;
            }
        }

        // Major type 7: floating-point numbers and other simple data types that need no content
        0xf4..=0xf7 => {}
        0xf8 => {
            r.seek(SeekFrom::Current(1))?;
        }
        0xf9 => {
            r.seek(SeekFrom::Current(2))?;
        }
        0xfa => {
            r.seek(SeekFrom::Current(4))?;
        }
        0xfb => {
            r.seek(SeekFrom::Current(8))?;
        }
        major => return Err(ParseError::UnexpectedCode(major)),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::references;

    fn bytes(s: &str) -> Vec<u8> {
        hex::decode(s.chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap()
    }

    #[test]
    fn references1() {
        let data = vec![
            bytes(
                r"
            6ffbd8e415444b5940d6fefacf64b922ad80b95debce812931745ad9b59b
            2565ea08b46db6da5052d6878c074d4f3e705d1a8456d1ae934b38b62e43
            6e413fbefb2284a5d628e2cf951722c04ff19ff217fcf0360fb8d27b55c0
            abe378984e0d07beeb964f9f4016408fa0c66b9bf445b53343be521290b9
            985e30d65c2116b852ab3414d65d6400dc4112ed278f83efc35e59a37b3e
            b62736dee6a752c331d78f176da7f1ad9bb5ed",
            ),
            bytes(
                r"
            a564747970656c776e66732f7075622f6469726776657273696f6e65302e
            322e30686d65746164617461a267637265617465641a643eddeb686d6f64
            69666965641a643eddeb6870726576696f757381d82a58250001711e2045
            c910e86e64f78a99dde9232e5978de40823eaa42732ff7a3814983d6969e
            7368757365726c616e64a16474657374d82a58250001711e2082a8fc238c
            9a05e2351f8ceaa4e5af2cdb39a895f6e929827a2614e61239d47c",
            ),
        ];
        for data in data {
            let mut links = Vec::new();
            references(&mut Cursor::new(&data), &mut links).unwrap();
            println!("{:?}", links);
        }
    }
}
