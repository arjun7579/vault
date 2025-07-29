use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{Read};
use zstd::stream::read::{Decoder as ZstdDecoder, Encoder as ZstdEncoder};

//enum to represent the different compression algorithms.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Deflate, // zlib
    Zstd,
    // more compression algo can be added
}

// function that takes a reader and returns a new, compressed reader.
pub fn compress_stream<'a, R: Read + 'a>(
    reader: R,
    algorithm: Algorithm,
) -> Box<dyn Read + 'a> {
    match algorithm {
        Algorithm::Deflate => Box::new(ZlibEncoder::new(reader, Compression::default())),
        Algorithm::Zstd => Box::new(ZstdEncoder::new(reader, 0).unwrap()),
    }
}

// function that takes a compressed reader and returns a decompressed reader.
pub fn decompress_stream<'a, R: Read + 'a>(
    reader: R,
    algorithm: Algorithm,
) -> Box<dyn Read + 'a> {
    match algorithm {
        Algorithm::Deflate => Box::new(ZlibDecoder::new(reader)),
        Algorithm::Zstd => Box::new(ZstdDecoder::new(reader).unwrap()),
    }
}