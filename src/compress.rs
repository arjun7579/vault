// compress.rs

use flate2::{write::DeflateEncoder, read::DeflateDecoder, Compression};
use std::io::{Read, Write, Result};

pub fn compress_f(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    let compressed_data = encoder.finish()?;
    Ok(compressed_data)
}

pub fn decompress_f(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;
    Ok(decompressed_data)
}
