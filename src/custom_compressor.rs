use std::collections::{HashMap, BinaryHeap};
use std::io::{self, Read, Write};
use std::cmp::Ordering;


#[derive(Debug, Clone)]
struct Node {
    freq: u64,
    byte: Option<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Eq for Node {}
impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.freq == other.freq
    }
}
impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        
        other.freq.cmp(&self.freq)
    }
}
impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//Core Huffman Logic 

fn build_frequency_map(data: &[u8]) -> HashMap<u8, u64> {
    let mut freq_map = HashMap::new();
    for &byte in data {
        *freq_map.entry(byte).or_insert(0) += 1;
    }
    freq_map
}

fn build_huffman_tree(freq_map: &HashMap<u8, u64>) -> Option<Box<Node>> {
    let mut heap = BinaryHeap::new();
    for (&byte, &freq) in freq_map {
        heap.push(Box::new(Node {
            freq,
            byte: Some(byte),
            left: None,
            right: None,
        }));
    }

    while heap.len() > 1 {
        let left = heap.pop().unwrap();
        let right = heap.pop().unwrap();
        let parent = Box::new(Node {
            freq: left.freq + right.freq,
            byte: None,
            left: Some(left),
            right: Some(right),
        });
        heap.push(parent);
    }
    heap.pop()
}

// Recursively traverses the tree to build the encoding map.
fn build_codes_recursive(node: &Node, prefix: Vec<bool>, codes: &mut HashMap<u8, Vec<bool>>) {
    if let Some(byte) = node.byte {
        // Edge Case: If the tree is just a single node (e.g., file with one unique byte) it needs a code. We assign '0' by convention.
        if prefix.is_empty() {
            codes.insert(byte, vec![false]);
        } else {
            codes.insert(byte, prefix);
        }
    } else {
        if let Some(ref left) = node.left {
            let mut left_prefix = prefix.clone();
            left_prefix.push(false);
            build_codes_recursive(left, left_prefix, codes);
        }
        if let Some(ref right) = node.right {
            let mut right_prefix = prefix.clone();
            right_prefix.push(true);
            build_codes_recursive(right, right_prefix, codes);
        }
    }
}

// Public API 
pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let freq_map = build_frequency_map(data);
    let tree = build_huffman_tree(&freq_map)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Cannot build Huffman tree"))?;
    
    let mut codes = HashMap::new();
    build_codes_recursive(&tree, Vec::new(), &mut codes);

    let mut encoded_data = Vec::new();
    let mut bit_buffer: u8 = 0;
    let mut bit_count: u8 = 0;

    for &byte in data {
        if let Some(code) = codes.get(&byte) {
            for &bit in code {
                bit_buffer = (bit_buffer << 1) | (bit as u8);
                bit_count += 1;
                if bit_count == 8 {
                    encoded_data.push(bit_buffer);
                    bit_buffer = 0;
                    bit_count = 0;
                }
            }
        }
    }

    if bit_count > 0 {
        bit_buffer <<= 8 - bit_count;
        encoded_data.push(bit_buffer);
    }

    // Serialize the frequency map to be used as the header for decompression.
    let header = bincode::serialize(&freq_map)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    let mut final_data = Vec::new();
    final_data.write_all(&(header.len() as u32).to_le_bytes())?;
    final_data.write_all(&header)?;
    final_data.write_all(&encoded_data)?;

    Ok(final_data)
}

pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut reader = io::Cursor::new(data);

    let mut header_len_buf = [0u8; 4];
    reader.read_exact(&mut header_len_buf)?;
    let header_len = u32::from_le_bytes(header_len_buf) as usize;

    let mut header_buf = vec![0u8; header_len];
    reader.read_exact(&mut header_buf)?;
    let freq_map: HashMap<u8, u64> = bincode::deserialize(&header_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let tree = build_huffman_tree(&freq_map)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Cannot rebuild Huffman tree"))?;

    let mut decompressed_data = Vec::new();
    let mut current_node = &tree;
    let total_bytes: u64 = freq_map.values().sum();

    let mut encoded_data = Vec::new();
    reader.read_to_end(&mut encoded_data)?;

    'outer: for byte in encoded_data {
        for i in (0..8).rev() {
            if decompressed_data.len() as u64 == total_bytes {
                break 'outer;
            }
            let bit = (byte >> i) & 1;
            
            current_node = match bit {
                1 => current_node.right.as_ref(),
                0 => current_node.left.as_ref(),
                _ => unreachable!(),
            }.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Malformed data: unexpected path in Huffman tree"))?;


            if let Some(decoded_byte) = current_node.byte {
                decompressed_data.push(decoded_byte);
                current_node = &tree;
            }
        }
    }

    Ok(decompressed_data)
}