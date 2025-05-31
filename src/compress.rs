use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;

#[derive(Debug, Eq, PartialEq)]
struct HuffmanNode {
    freq: usize,
    byte: Option<u8>, // None for internal nodes
    left: Option<Box<HuffmanNode>>,
    right: Option<Box<HuffmanNode>>,
}

// For BinaryHeap to become a min-heap based on freq
impl Ord for HuffmanNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap
        other.freq.cmp(&self.freq)
    }
}
impl PartialOrd for HuffmanNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Build Huffman tree from frequency map
fn build_tree(freqs: &HashMap<u8, usize>) -> Option<Box<HuffmanNode>> {
    let mut heap = BinaryHeap::new();

    for (&byte, &freq) in freqs.iter() {
        heap.push(HuffmanNode {
            freq,
            byte: Some(byte),
            left: None,
            right: None,
        });
    }

    while heap.len() > 1 {
        let left = heap.pop().unwrap();
        let right = heap.pop().unwrap();

        heap.push(HuffmanNode {
            freq: left.freq + right.freq,
            byte: None,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        });
    }

    heap.pop().map(Box::new)
}

/// Generate Huffman codes (byte -> bitstring) from tree
fn generate_codes(node: &HuffmanNode, prefix: Vec<bool>, codes: &mut HashMap<u8, Vec<bool>>) {
    if let Some(byte) = node.byte {
        codes.insert(byte, prefix);
    } else {
        let mut left_prefix = prefix.clone();
        left_prefix.push(false);
        if let Some(ref left) = node.left {
            generate_codes(left, left_prefix, codes);
        }
        let mut right_prefix = prefix;
        right_prefix.push(true);
        if let Some(ref right) = node.right {
            generate_codes(right, right_prefix, codes);
        }
    }
}

/// Write bits to a Vec<u8> as bytes
struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.flush_byte();
        }
    }

    fn write_bits(&mut self, bits: &[bool]) {
        for &bit in bits {
            self.write_bit(bit);
        }
    }

    fn flush_byte(&mut self) {
        self.buffer.push(self.current_byte);
        self.current_byte = 0;
        self.bit_pos = 0;
    }

    fn into_bytes(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.flush_byte();
        }
        self.buffer
    }
}

/// Read bits from &[u8]
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] & (1 << (7 - self.bit_pos))) != 0;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }
}

/// Compress data using Huffman coding
pub fn compress(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![];
    }

    // 1. Count frequencies
    let mut freqs = HashMap::new();
    for &b in data {
        *freqs.entry(b).or_insert(0) += 1;
    }

    // 2. Build Huffman tree
    let tree = build_tree(&freqs).expect("Huffman tree must be built");

    // 3. Generate codes
    let mut codes = HashMap::new();
    generate_codes(&tree, Vec::new(), &mut codes);

    // 4. Serialize tree for decompression
    // We'll serialize tree using a pre-order traversal:
    // For each node:
    // - write 1 bit: 1 if leaf, 0 if internal
    // - if leaf: write 8 bits for byte
    // Return a Vec<u8> of the serialized tree bits
    let mut tree_bits = BitWriter::new();
    fn serialize_tree(node: &HuffmanNode, writer: &mut BitWriter) {
        if let Some(byte) = node.byte {
            writer.write_bit(true);
            for i in (0..8).rev() {
                writer.write_bit((byte >> i) & 1 == 1);
            }
        } else {
            writer.write_bit(false);
            if let Some(ref left) = node.left {
                serialize_tree(left, writer);
            }
            if let Some(ref right) = node.right {
                serialize_tree(right, writer);
            }
        }
    }
    serialize_tree(&tree, &mut tree_bits);
    let tree_bytes = tree_bits.into_bytes();

    // 5. Encode data bits
    let mut data_bits = BitWriter::new();
    for &b in data {
        let code = &codes[&b];
        data_bits.write_bits(code);
    }
    let data_bytes = data_bits.into_bytes();

    // 6. Final output: [tree length (u32 LE)][tree bytes][data bytes]
    let mut output = Vec::new();
    let tree_len = tree_bytes.len() as u32;
    output.extend_from_slice(&tree_len.to_le_bytes());
    output.extend_from_slice(&tree_bytes);
    output.extend_from_slice(&data_bytes);

    output
}

/// Decompress data compressed by above compress()
pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    // 1. Read tree length
    let tree_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + tree_len {
        return None;
    }

    let tree_data = &data[4..4 + tree_len];
    let encoded_data = &data[4 + tree_len..];

    // 2. Deserialize Huffman tree
    let mut reader = BitReader::new(tree_data);
    fn deserialize_tree(reader: &mut BitReader) -> Option<Box<HuffmanNode>> {
        let is_leaf = reader.read_bit()?;
        if is_leaf {
            let mut byte = 0u8;
            for _ in 0..8 {
                let bit = reader.read_bit()?;
                byte = (byte << 1) | if bit { 1 } else { 0 };
            }
            Some(Box::new(HuffmanNode {
                freq: 0,
                byte: Some(byte),
                left: None,
                right: None,
            }))
        } else {
            let left = deserialize_tree(reader)?;
            let right = deserialize_tree(reader)?;
            Some(Box::new(HuffmanNode {
                freq: 0,
                byte: None,
                left: Some(left),
                right: Some(right),
            }))
        }
    }
    let tree = deserialize_tree(&mut reader)?;

    // 3. Decode data bits using tree
    let mut data_reader = BitReader::new(encoded_data);
    let mut output = Vec::new();

    while let Some(byte) = decode_byte(&tree, &mut data_reader) {
        output.push(byte);
    }

    Some(output)
}

/// Helper: decode one byte from bitstream using tree
fn decode_byte(node: &HuffmanNode, reader: &mut BitReader) -> Option<u8> {
    let mut current = node;

    loop {
        if let Some(byte) = current.byte {
            return Some(byte);
        }

        let bit = reader.read_bit()?;
        current = if bit {
            current.right.as_ref()?
        } else {
            current.left.as_ref()?
        };
    }
}
