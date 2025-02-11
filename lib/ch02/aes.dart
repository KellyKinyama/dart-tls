import 'dart:typed_data';

import 'aes_tables.dart';

void memcpy(List<Uint8List> target, Uint8List src, int len) {
  for (int i = 0; i < len; i++) {
    target[i] = src.sublist(i * 4, i * 4 + 4);
  }
}

void xor(Uint8List target, Uint8List src, int len) {
  for (int i = 0; i < target.length; i++) {
    target[i] ^= src[i];
  }
}

void rot_word(Uint8List w) {
  int tmp;

  tmp = w[0];
  w[0] = w[1];
  w[1] = w[2];
  w[2] = w[3];
  w[3] = tmp;
}

void sub_word(Uint8List w) {
  int i = 0;

  for (i = 0; i < 4; i++) {
    w[i] = sbox[(w[i] & 0xF0) >> 4][w[i] & 0x0F];
  }
}

void compute_key_schedule(List<int> key, int key_length, List<Uint8List> w) {
  int i;
  int key_words = key_length >> 2;
  int rcon = 0x01;

  // First, copy the key directly into the key schedule
  memcpy(w, Uint8List.fromList(key), key_length);
  for (i = key_words; i < 4 * (key_words + 7); i++) {
    memcpy([w[i]], w[i - 1], 4);
    if ((i % key_words) == 0) {
      rot_word(w[i]);
      sub_word(w[i]);
      if ((i % 36) == 0) {
        rcon = 0x1b;
      }
      w[i][0] ^= rcon;
      rcon <<= 1;
    } else if ((key_words > 6) && ((i % key_words) == 4)) {
      sub_word(w[i]);
    }
    w[i][0] ^= w[i - key_words][0];
    w[i][1] ^= w[i - key_words][1];
    w[i][2] ^= w[i - key_words][2];
    w[i][3] ^= w[i - key_words][3];
  }
}

void add_round_key(List<List<int>> state, List<List<int>> w) {
  int c, r;

  for (c = 0; c < 4; c++) {
    for (r = 0; r < 4; r++) {
      state[r][c] = state[r][c] ^ w[c][r];
    }
  }
}

void sub_bytes(List<List<int>> state) {
  int r, c;

  for (r = 0; r < 4; r++) {
    for (c = 0; c < 4; c++) {
      state[r][c] = sbox[(state[r][c] & 0xF0) >> 4][state[r][c] & 0x0F];
    }
  }
}

void shift_rows(List<List<int>> state) {
  int tmp;

  tmp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = tmp;

  tmp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = tmp;
  tmp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = tmp;

  tmp = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = state[3][0];
  state[3][0] = tmp;
}

int xtime(int x) {
  return (x << 1) ^ (((x & 0x80) != 0) ? 0x1b : 0x00);
}

int dot(int x, int y) {
  int mask;
  int product = 0;

  for (mask = 0x01; mask != 0; mask <<= 1) {
    if (y & mask != 0) {
      product ^= x;
    }
    x = xtime(x);
  }

  return product;
}

void mix_columns(List<List<int>> s) {
  int c;
  List<int> t = [];

  for (c = 0; c < 4; c++) {
    t[0] = dot(2, s[0][c]) ^ dot(3, s[1][c]) ^ s[2][c] ^ s[3][c];
    t[1] = s[0][c] ^ dot(2, s[1][c]) ^ dot(3, s[2][c]) ^ s[3][c];
    t[2] = s[0][c] ^ s[1][c] ^ dot(2, s[2][c]) ^ dot(3, s[3][c]);
    t[3] = dot(3, s[0][c]) ^ s[1][c] ^ s[2][c] ^ dot(2, s[3][c]);
    s[0][c] = t[0];
    s[1][c] = t[1];
    s[2][c] = t[2];
    s[3][c] = t[3];
  }
}


void aes_block_encrypt( List<int> input_block,
                List<int> output_block,
                List<int> key,
                int key_size )
{
  int r, c;
  int round;
  int nr;
  List<List<int>> state=[];
  List<List<int>> w=[];

  for ( r = 0; r < 4; r++ )
  {
    for ( c = 0; c < 4; c++ )
    {
      state[ r ][ c ] = input_block[ r + ( 4 * c ) ];
    }
  }
  // rounds = key size in 4-byte words + 6
  nr = ( key_size >> 2 ) + 6;
  
  compute_key_schedule( key, key_size, [w] );
  
  add_round_key( state, w[ 0 ] );

  for ( round = 0; round < nr; round++ )
  {
    sub_bytes( state );
    shift_rows( state );
    if ( round < ( nr - 1 ) )
    {
      mix_columns( state );
    }
    add_round_key( state, w[ ( round + 1 ) * 4 ] );
  }

  for ( r = 0; r < 4; r++ )
  { 
    for ( c = 0; c < 4; c++ )
    {
      output_block[ r + ( 4 * c ) ] = state[ r ][ c ];
    }
  }
}