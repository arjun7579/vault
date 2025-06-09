use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
struct Node {
    freq: usize,
    byte: Option<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

// Implement ordering for min-heap
impl Eq for Node {}
impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.freq == other.freq
    }
}
impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        // First by frequency (reverse for min-heap)
        let freq_cmp = other.freq.cmp(&self.freq);
        if freq_cmp != Ordering::Equal {
            return freq_cmp;
        }
        // Then by byte value (None is considered greater than Some)
        match (self.byte, other.byte) {
            (Some(a), Some(b)) => b.cmp(&a), // reverse for min-heap
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (None, None) => Ordering::Equal,
        }
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


/// Build frequency map from input data
fn build_frequency_map(data: &[u8]) -> HashMap<u8, usize> {
    let mut freq_map = HashMap::new();
    for &byte in data {
        *freq_map.entry(byte).or_insert(0) += 1;
    }
    freq_map
}

/// Build Huffman tree from frequency map
fn build_huffman_tree(freq_map: &HashMap<u8, usize>) -> Option<Box<Node>> {
    let mut nodes: Vec<Box<Node>> = freq_map
        .iter()
        .map(|(&byte, &freq)| Box::new(Node {
            freq,
            byte: Some(byte),
            left: None,
            right: None,
        }))
        .collect();

    // Sort by freq, then by byte value for deterministic tie-breaking
    nodes.sort_by(|a, b| {
        a.freq.cmp(&b.freq)
            .then_with(|| a.byte.cmp(&b.byte))
    });

    while nodes.len() > 1 {
        let left = nodes.remove(0);
        let right = nodes.remove(0);
        let parent = Box::new(Node {
            freq: left.freq + right.freq,
            byte: None,
            left: Some(left),
            right: Some(right),
        });
        // Insert and keep sorted
        let pos = nodes.binary_search_by(|n| {
            n.freq.cmp(&parent.freq)
                .then_with(|| n.byte.cmp(&parent.byte))
        }).unwrap_or_else(|e| e);
        nodes.insert(pos, parent);
    }

    nodes.pop()
}


/// Recursively build code map: byte → Vec<bool>
fn build_codes(node: &Node, prefix: Vec<bool>, map: &mut HashMap<u8, Vec<bool>>) {
    if let Some(byte) = node.byte {
        map.insert(byte, prefix);
    } else {
        if let Some(ref left) = node.left {
            let mut left_prefix = prefix.clone();
            left_prefix.push(false);
            build_codes(left, left_prefix, map);
        }
        if let Some(ref right) = node.right {
            let mut right_prefix = prefix.clone();
            right_prefix.push(true);
            build_codes(right, right_prefix, map);
        }
    }
}

/// Build fast lookup table: byte → (code bits, bit length)
fn build_lookup_table(code_map: &HashMap<u8, Vec<bool>>) -> [(u64, u8); 256] {
    let mut table = [(0u64, 0u8); 256];
    for (&byte, code_bits) in code_map {
        let mut code: u64 = 0;
        for &bit in code_bits {
            code = (code << 1) | (bit as u64);
        }
        table[byte as usize] = (code, code_bits.len() as u8);
    }
    table
}

/// Compress data using Huffman coding and lookup table
pub fn compress_f(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(vec![]);
    }

    let freq_map = build_frequency_map(data);
    let tree = build_huffman_tree(&freq_map)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to build tree"))?;

    let mut code_map = HashMap::new();
    build_codes(&tree, vec![], &mut code_map);
    let lookup_table = build_lookup_table(&code_map);

    // Write header: num entries + (byte, freq) pairs + bit count
    let mut out = Vec::new();
    out.write_all(&(freq_map.len() as u16).to_le_bytes())?;
    for (&byte, &freq) in &freq_map {
        out.write_all(&[byte])?;
        out.write_all(&(freq as u64).to_le_bytes())?;
    }

    // Encode data using lookup table
    let mut bit_buffer: u64 = 0;
    let mut bit_count: u8 = 0;
    let mut total_bits: u64 = 0;
    let mut encoded_bytes = Vec::new();

    for &byte in data {
        let (code, len) = lookup_table[byte as usize];
        bit_buffer = (bit_buffer << len) | code;
        bit_count += len;
        total_bits += len as u64;

        while bit_count >= 8 {
            let shift = bit_count - 8;
            encoded_bytes.push((bit_buffer >> shift) as u8);
            bit_buffer &= (1 << shift) - 1;
            bit_count -= 8;
        }
    }
    if bit_count > 0 {
        encoded_bytes.push((bit_buffer << (8 - bit_count)) as u8);
    }

    // Write total bit count (for correct decoding of padding)
    out.write_all(&total_bits.to_le_bytes())?;
    out.extend_from_slice(&encoded_bytes);

    Ok(out)
}

/// Decompress Huffman-encoded data
pub fn decompress_f(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(data);

    // Read frequency table
    let mut len_buf = [0u8; 2];
    if cursor.read_exact(&mut len_buf).is_err() {
        return Ok(vec![]);
    }
    let entries = u16::from_le_bytes(len_buf) as usize;

    let mut freq_map = HashMap::new();
    for _ in 0..entries {
        let mut byte_buf = [0u8; 1];
        let mut freq_buf = [0u8; 8];
        cursor.read_exact(&mut byte_buf)?;
        cursor.read_exact(&mut freq_buf)?;
        freq_map.insert(byte_buf[0], u64::from_le_bytes(freq_buf) as usize);
    }

    let tree = build_huffman_tree(&freq_map)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to build tree"))?;

    // Read total bit count
    let mut bitcount_buf = [0u8; 8];
    cursor.read_exact(&mut bitcount_buf)?;
    let total_bits = u64::from_le_bytes(bitcount_buf);

    // Decode bits
    let bit_data = &data[cursor.position() as usize..];
    let mut result = Vec::new();
    let mut current = &tree;
    let mut bits_read = 0u64;

    for &byte in bit_data {
        for i in 0..8 {
            if bits_read == total_bits {
                break;
            }
            let bit = (byte & (1 << (7 - i))) != 0;
            current = if bit {
                current.right.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid bit sequence"))?
            } else {
                current.left.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid bit sequence"))?
            };

            if let Some(b) = current.byte {
                result.push(b);
                current = &tree;
            }
            bits_read += 1;
        }
        if bits_read == total_bits {
            break;
        }
    }

    Ok(result)
}


