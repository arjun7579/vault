use std::collections::{BinaryHeap, HashMap};
use std::io::{Cursor, Read, Write};
use std::cmp::Ordering;
use bitstream_io::{BitWriter, BitReader, BE};

#[derive(Debug)]
struct Node {
    freq: usize,
    byte: Option<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Node {
    fn new_leaf(byte: u8, freq: usize) -> Self {
        Node { freq, byte: Some(byte), left: None, right: None }
    }

    fn new_internal(freq: usize, left: Node, right: Node) -> Self {
        Node {
            freq,
            byte: None,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    fn is_leaf(&self) -> bool {
        self.byte.is_some()
    }
}

impl Eq for Node {}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.freq == other.freq
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse to make BinaryHeap a min-heap
        other.freq.cmp(&self.freq)
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Builds a frequency map
fn build_freq_map(data: &[u8]) -> HashMap<u8, usize> {
    let mut freq = HashMap::new();
    for &b in data {
        *freq.entry(b).or_insert(0) += 1;
    }
    freq
}

/// Builds a Huffman tree from a frequency map
fn build_tree(freq_map: &HashMap<u8, usize>) -> Node {
    let mut heap = BinaryHeap::new();

    for (&byte, &freq) in freq_map {
        heap.push(Node::new_leaf(byte, freq));
    }

    while heap.len() > 1 {
        let left = heap.pop().unwrap();
        let right = heap.pop().unwrap();
        let merged = Node::new_internal(left.freq + right.freq, left, right);
        heap.push(merged);
    }

    heap.pop().unwrap()
}

/// Recursively builds Huffman codes from tree
fn build_codes(node: &Node, prefix: Vec<bool>, codes: &mut HashMap<u8, Vec<bool>>) {
    if let Some(b) = node.byte {
        codes.insert(b, prefix);
        return;
    }

    if let Some(ref left) = node.left {
        let mut left_prefix = prefix.clone();
        left_prefix.push(false);
        build_codes(left, left_prefix, codes);
    }

    if let Some(ref right) = node.right {
        let mut right_prefix = prefix.clone();
        right_prefix.push(true);
        build_codes(right, right_prefix, codes);
    }
}

/// Serialize tree into bitstream (pre-order)
fn write_tree(node: &Node, writer: &mut BitWriter<BE, Vec<u8>>) {
    if node.is_leaf() {
        writer.write_bit(true).unwrap();
        writer.write(8, node.byte.unwrap()).unwrap();
    } else {
        writer.write_bit(false).unwrap();
        write_tree(node.left.as_ref().unwrap(), writer);
        write_tree(node.right.as_ref().unwrap(), writer);
    }
}

/// Deserialize tree from bitstream (pre-order)
fn read_tree(reader: &mut BitReader<BE, Cursor<&[u8]>>) -> Node {
    let is_leaf = reader.read_bit().unwrap();
    if is_leaf {
        let byte = reader.read::<u8>(8).unwrap();
        Node::new_leaf(byte, 0)
    } else {
        let left = read_tree(reader);
        let right = read_tree(reader);
        Node::new_internal(0, left, right)
    }
}

/// Compresses input data using Huffman coding
pub fn compress(data: &[u8]) -> Vec<u8> {
    let freq_map = build_freq_map(data);
    let tree = build_tree(&freq_map);

    let mut codes = HashMap::new();
    build_codes(&tree, vec![], &mut codes);

    let mut output = Vec::new();
    let mut writer = BitWriter::endian(&mut output, BE);

    // Write the Huffman tree
    write_tree(&tree, &mut writer);

    // Write number of bytes
    writer.write(32, data.len() as u32).unwrap();

    // Write encoded data
    for &b in data {
        let bits = &codes[&b];
        for &bit in bits {
            writer.write_bit(bit).unwrap();
        }
    }

    writer.byte_align().unwrap();
    output
}

/// Decompresses Huffman-compressed data
pub fn decompress(data: &[u8]) -> Vec<u8> {
    let mut reader = BitReader::endian(Cursor::new(data), BE);

    // Read tree
    let tree = read_tree(&mut reader);

    // Read original byte count
    let original_len = reader.read::<u32>(32).unwrap();

    // Decode bits using tree
    let mut result = Vec::with_capacity(original_len as usize);
    for _ in 0..original_len {
        let mut node = &tree;
        while !node.is_leaf() {
            let bit = reader.read_bit().unwrap();
            node = if bit {
                node.right.as_ref().unwrap()
            } else {
                node.left.as_ref().unwrap()
            };
        }
        result.push(node.byte.unwrap());
    }

    result
}
