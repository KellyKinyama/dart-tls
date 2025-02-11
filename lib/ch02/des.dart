import 'dart:typed_data';

import 'des_tables.dart';

int getBit(Uint8List array, int bit) {
  return array[bit ~/ 8] & (0x80 >> (bit % 8));
}

void setBit(Uint8List array, int bit) {
  array[bit ~/ 8] |= (0x80 >> (bit % 8));
}

void clearBit(Uint8List array, int bit) {
  array[bit ~/ 8] &= ~(0x80 >> (bit % 8));
}

void xor(Uint8List target, Uint8List src, int len) {
  for (int i = 0; i < target.length; i++) {
    target[i] ^= src[i];
  }
}

void rol(Uint8List target) {
  int carryLeft = (target[0] & 0x80) >> 3;
  target[0] = (target[0] << 1) | ((target[1] & 0x80) >> 7);
  target[1] = (target[1] << 1) | ((target[2] & 0x80) >> 7);
  target[2] = (target[2] << 1) | ((target[3] & 0x80) >> 7);
  int carryRight = (target[3] & 0x08) >> 3;
  target[3] =
      (((target[3] << 1) | ((target[4] & 0x80) >> 7)) & ~0x10) | carryLeft;
  target[4] = (target[4] << 1) | ((target[5] & 0x80) >> 7);
  target[5] = (target[5] << 1) | ((target[6] & 0x80) >> 7);
  target[6] = (target[6] << 1) | carryRight;
}

void ror(Uint8List target) {
  int carryRight = (target[6] & 0x01) << 3;
  target[6] = (target[6] >> 1) | ((target[5] & 0x01) << 7);
  target[5] = (target[5] >> 1) | ((target[4] & 0x01) << 7);
  target[4] = (target[4] >> 1) | ((target[3] & 0x01) << 7);
  int carryLeft = (target[3] & 0x10) << 3;
  target[3] =
      (((target[3] >> 1) | ((target[2] & 0x01) << 7)) & ~0x08) | carryRight;
  target[2] = (target[2] >> 1) | ((target[1] & 0x01) << 7);
  target[1] = (target[1] >> 1) | ((target[0] & 0x01) << 7);
  target[0] = (target[0] >> 1) | carryLeft;
}

const int desBlockSize = 8;
const int expansionBlockSize = 6;
const int subkeySize = 6;

enum Operation { encrypt, decrypt }

// void permute(Uint8List output, Uint8List input, List<int> table) {
//   for (int i = 0; i < table.length; i++) {
//     int bit = ((input[(table[i] - 1) ~/ 8] >> (7 - ((table[i] - 1) % 8))) & 1);
//     output[i ~/ 8] |= bit << (7 - (i % 8));
//   }
// }

/**
 * Implement the initial and final permutation functions. permute_table
 * and target must have exactly len and len * 8 number of entries,
 * respectively, but src can be shorter (expansion function depends on this).
 * NOTE: this assumes that the permutation tables are defined as one-based
 * rather than 0-based arrays, since they're given that way in the
 * specification.
 */
void permute(
    Uint8List target, Uint8List src, List<int> permute_table, int len) {
  int i;
  for (i = 0; i < len * 8; i++) {
    if (getBit(src, (permute_table[i] - 1)) != 0) {
      setBit(target, i);
    } else {
      clearBit(target, i);
    }
  }
}

Uint8List xorBlocks(Uint8List a, Uint8List b) {
  Uint8List result = Uint8List(a.length);
  for (int i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

void desBlockOperate(Uint8List plaintext, Uint8List ciphertext, Uint8List key,
    OpType operation, int triplicate) {
  Uint8List ipBlock = Uint8List(8);
  Uint8List expansionBlock = Uint8List(6);
  Uint8List substitutionBlock = Uint8List(4);
  Uint8List pboxTarget = Uint8List(4);
  Uint8List recombBox = Uint8List(4);
  Uint8List pc1Key = Uint8List(7);
  Uint8List subkey = Uint8List(6);

  // Initial permutation
  permute(ipBlock, plaintext, ipTable, 8);

  // Key schedule computation
  permute(pc1Key, key, pc1Table, 7);

  for (int round = 0; round < 16; round++) {
    // Feistel function
    permute(expansionBlock, ipBlock.sublist(4, 8), expansionTable, 6);

    // Key scheduling
    if (operation == OpType.encrypt) {
      rol(pc1Key);
      if (!(round <= 1 || round == 8 || round == 15)) {
        rol(pc1Key);
      }
    }

    permute(subkey, pc1Key, pc2Table, 6);

    if (operation == OpType.decrypt) {
      ror(pc1Key);
      if (!(round >= 14 || round == 7 || round == 0)) {
        ror(pc1Key);
      }
    }

    xor(expansionBlock, subkey, 6);

    // Substitution
    substitutionBlock.fillRange(0, 4, 0);
    substitutionBlock[0] = (sBox[0][(expansionBlock[0] & 0xFC) >> 2] << 4) |
        sBox[1][((expansionBlock[0] & 0x03) << 4) |
            ((expansionBlock[1] & 0xF0) >> 4)];
    substitutionBlock[1] = (sBox[2][((expansionBlock[1] & 0x0F) << 2) |
                ((expansionBlock[2] & 0xC0) >> 6)] <<
            4) |
        sBox[3][(expansionBlock[2] & 0x3F)];
    substitutionBlock[2] = (sBox[4][(expansionBlock[3] & 0xFC) >> 2] << 4) |
        sBox[5][((expansionBlock[3] & 0x03) << 4) |
            ((expansionBlock[4] & 0xF0) >> 4)];
    substitutionBlock[3] = (sBox[6][((expansionBlock[4] & 0x0F) << 2) |
                ((expansionBlock[5] & 0xC0) >> 6)] <<
            4) |
        sBox[7][(expansionBlock[5] & 0x3F)];

    // Permutation
    permute(pboxTarget, substitutionBlock, pTable, 4);

    // Recombination
    recombBox.setAll(0, ipBlock.sublist(0, 4));
    ipBlock.setAll(0, ipBlock.sublist(4, 8));
    xor(recombBox, pboxTarget, 4);
    ipBlock.setAll(4, recombBox);
  }

  // Final swap
  recombBox.setAll(0, ipBlock.sublist(0, 4));
  ipBlock.setAll(0, ipBlock.sublist(4, 8));
  ipBlock.setAll(4, recombBox);

  // Final permutation
  permute(ciphertext, ipBlock, fpTable, 8);
}

void desOperate(
    Uint8List input, Uint8List output, Uint8List key, Operation op) {
  for (int i = 0; i < input.length; i += desBlockSize) {
    Uint8List block = input.sublist(i, i + desBlockSize);
    Uint8List result = Uint8List(desBlockSize);
    desBlockOperate(block, result, key,
        op == Operation.encrypt ? OpType.encrypt : OpType.decrypt, 0);
    output.setRange(i, i + desBlockSize, result);
  }
}

void desEncrypt(Uint8List plaintext, Uint8List ciphertext, Uint8List key) {
  desOperate(plaintext, ciphertext, key, Operation.encrypt);
}
