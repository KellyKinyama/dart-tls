// This does not return a 1 for a 1 bit; it just returns non-zero
import 'dart:typed_data';

bool getBit(Uint8List array, int bit) {
  return (array[bit ~/ 8] & (0x80 >> (bit % 8))) != 0;
}

void setBit(Uint8List array, int bit) {
  array[bit ~/ 8] |= (0x80 >> (bit % 8));
}

void clearBit(Uint8List array, int bit) {
  array[bit ~/ 8] &= ~(0x80 >> (bit % 8));
}

void xor(Uint8List target, Uint8List src, int len) {
  for (int i = 0; i < len; i++) {
    target[i] ^= src[i];
  }
}

/**
 * Implement the initial and final permutation functions. permute_table
 * and target must have exactly len and len * 8 number of entries,
 * respectively, but src can be shorter (expansion function depends on this).
 * NOTE: this assumes that the permutation tables are defined as one-based
 * rather than 0-based arrays, since they’re given that way in the
 * specification.
 */
void permute(Uint8List target, Uint8List src, List<int> permuteTable, int len) {
  for (int i = 0; i < len * 8; i++) {
    if (getBit(src, permuteTable[i] - 1)) {
      setBit(target, i);
    } else {
      clearBit(target, i);
    }
  }
}

void main() {
  Uint8List bitArray = Uint8List(1); // 8 bits

  setBit(bitArray, 3);
  print(getBit(bitArray, 3)); // true

  clearBit(bitArray, 3);
  print(getBit(bitArray, 3)); // false

  Uint8List target = Uint8List.fromList([0xAA, 0xBB, 0xCC]);
  Uint8List src = Uint8List.fromList([0xFF, 0x00, 0xFF]);

  xor(target, src, target.length);

  print(target); // Expected output: [0x55, 0xBB, 0x33]

  //permute
  src = Uint8List.fromList([0xAA]); // Example 8-bit source
  target = Uint8List(1); // 8-bit target (1 byte)
  List<int> permuteTable = [
    8,
    7,
    6,
    5,
    4,
    3,
    2,
    1
  ]; // Example permutation table

  permute(target, src, permuteTable, 1);
  print(target[0]
      .toRadixString(2)
      .padLeft(8, '0')); // Expected output: "01010101"
}
