// src/compress.rs
use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use zstd::stream::read::{Decoder as ZstdDecoder, Encoder as ZstdEncoder};

/// Enum representing the different compression algorithms.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Zstd,
    Deflate,
}

/// Takes a reader and returns a new, compressed reader.
pub fn compress_stream<'a, R: Read + 'a>(
    reader: R,
    algorithm: Algorithm,
) -> Box<dyn Read + 'a> {
    match algorithm {
        Algorithm::Zstd => Box::new(ZstdEncoder::new(reader, 0).unwrap()),
        Algorithm::Deflate => Box::new(ZlibEncoder::new(reader, Compression::default())),
    }
}

/// Takes a compressed reader and returns a decompressed reader.
pub fn decompress_stream<'a, R: Read + 'a>(
    reader: R,
    algorithm: Algorithm,
) -> Box<dyn Read + 'a> {
    match algorithm {
        Algorithm::Zstd => Box::new(ZstdDecoder::new(reader).unwrap()),
        Algorithm::Deflate => Box::new(ZlibDecoder::new(reader)),
    }
}