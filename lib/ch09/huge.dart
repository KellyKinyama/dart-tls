class Huge {
  int sign;
  int size;
  List<int> rep;

  Huge(this.sign, this.size, this.rep);
}

// /**
//  * Extend the space for h by 1 char and set the LSB of that int
//  * to 1.
//  */
void expand(Huge h) {
  List<int> tmp = h.rep;
  h.size++;
  // h.rep = ( unsigned char * )
  //   calloc( h.size, sizeof( unsigned char ) );
  // memcpy( h.rep + 1, tmp,
  //   ( h.size - 1 ) * sizeof( unsigned char ) );
  // h.rep[ 0 ] = 0x01;
  // free( tmp );
}

// /**
//  * Given a byte array, load it into a "huge", aligning integers
//  * appropriately
//  */
Huge load_huge(List<int> bytes, int length) {
  return Huge(0, length, bytes);
}

void unload_huge(final Huge h, List<int> bytes, int length) {
  // memcpy( bytes + ( length - h.size ), h.rep, length );
}

// /**
//  * Add two Huges - overwrite h1 with the result.
//  */
void add_magnitude(Huge h1, Huge h2) {
  int i, j;
  int sum;
  int carry = 0;

  // Adding h2 to h1. If h2 is > h1 to begin with, resize h1.
  if (h2.size > h1.size) {
    List<int> tmp = h1.rep;
    // h1.rep = ( unsigned char * ) calloc( h2.size,
    //   sizeof( unsigned char ) );
    // memcpy( h1.rep + ( h2.size - h1.size ), tmp, h1.size );
    // h1.size = h2.size;
    // free( tmp );
  }

  i = h1.size;
  j = h2.size;

  do {
    i--;
    if (j != 0) {
      j--;
      sum = h1.rep[i] + h2.rep[j] + carry;
    } else {
      sum = h1.rep[i] + carry;
    }

    carry = sum > 0xFF ? 1 : 0;
    h1.rep[i] = sum;
  } while (i != 0);

  if (carry != 0) {
    // Still overflowed; allocate more space
    expand(h1);
  }
}

// /**
//  * Go through h and see how many of the left-most bytes are unused.
//  * Remove them and resize h appropriately.
//  */
void contract(Huge h) {
  int i = 0;

  while ((h.rep[i] == 0) && (i < h.size)) {
    i++;
  }

  if (i != 0 && i < h.size) {
    int tmp = h.rep[i];
    // h.rep = ( unsigned char * ) calloc( h.size - i,
    //   sizeof( unsigned char ) );
    // memcpy( h.rep, tmp, h.size - i );
    h.size -= i;
  }
}

void subtract_magnitude(Huge h1, Huge h2) {
  int i = h1.size;
  int j = h2.size;
  int difference; // signed int - important!
  int borrow = 0;

  do {
    i--;

    if (j != 0) {
      j--;
      difference = h1.rep[i] - h2.rep[j] - borrow;
    } else {
      difference = h1.rep[i] - borrow;
    }
    borrow = (difference < 0) ? 1 : 0;
    h1.rep[i] = difference;
  } while (i != 0);

  if (borrow != 0 && i != 0) {
    if (h1.rep[i - 1] != 0) // Don't borrow i
    {
      // negative reults are now OK
      h1.rep[i - 1]--;
    }
  }

  contract(h1);
}

void add(Huge h1, Huge h2) {
  int result_sign;

  // First compute sign of result, then compute magnitude
  if (compare(h1, h2) > 0) {
    result_sign = h1.sign;

    if (h1.sign == h2.sign) {
      add_magnitude(h1, h2);
    } else {
      subtract_magnitude(h1, h2);
    }
  } else {
    Huge tmp = set_huge(0);
    ;

    // put h1 into tmp and h2 into h1 to swap the operands
    // set_huge( tmp, 0 ); // initialize
    copy_huge(tmp, h1);
    copy_huge(h1, h2);

    if (h1.sign == tmp.sign) {
      result_sign = h1.sign;
      add_magnitude(h1, tmp);
    } else {
      result_sign = h2.sign;
      subtract_magnitude(h1, tmp);
    }

    // free_huge( tmp );
  }

  // Use the stored sign to set the result
  h1.sign = result_sign;
}

void subtract(Huge h1, Huge h2) {
  int result_sign;

  // First compute sign of result, then compute magnitude
  if (compare(h1, h2) > 0) {
    result_sign = h1.sign;

    if (h1.sign == h2.sign) {
      subtract_magnitude(h1, h2);
    } else {
      add_magnitude(h1, h2);
    }
  } else {
    Huge tmp = set_huge(0);

    // put h1 into tmp and h2 into h1 to swap the operands
    // set_huge( tmp, 0 ); // initialize
    copy_huge(tmp, h1);
    copy_huge(h1, h2);

    if (h1.sign == tmp.sign) {
      result_sign = (h1.sign == 0) ? 0 : 1;
      subtract_magnitude(h1, tmp);
    } else {
      result_sign = (h1.sign == 0) ? 0 : 1;
      add_magnitude(h1, tmp);
    }

    // free_huge( &tmp );
  }

  // Use the stored sign to set the result
  h1.sign = result_sign;
}

void copy_huge(Huge tgt, Huge src) {
  // if ( tgt.rep )
  // {
  //   free( tgt.rep );
  // }

  tgt.sign = src.sign;
  tgt.size = src.size;
  tgt.rep = src.rep;
  // tgt.rep = ( unsigned char * )
  //   calloc( src.size, sizeof( unsigned char ) );
  // memcpy( tgt.rep, src.rep,
  //    ( src.size * sizeof( unsigned char ) ) );
}

// void free_huge( Huge h )
// {
//   if ( h.rep )
//   {
//     free( h.rep );
//   }
// }

Huge set_huge(int val) {
  int mask, i, shift;
  // Negative number support
  final sign = 0; // sign of 0 means positive

  int size = 4;

  // Figure out the minimum amount of space this "val" will take
  // up in chars (leave at least one byte, though, if �val� is 0).
  for (mask = 0xFF000000; mask > 0x000000FF; mask >>= 8) {
    if (val & mask != 0) {
      break;
    }
    size--;
  }

  // h.rep = List.filled( h.size,0 );
  final data = List.filled(size, 0);

  // Now work backwards through the int, masking off each 8-bit
  // byte (up to the first 0 byte) and copy it into the �huge�
  // array in big-endian format.
  mask = 0x000000FF;
  shift = 0;
  for (i = size; i != 0; i--) {
    data[i - 1] = (val & mask) >> shift;
    mask <<= 8;
    shift += 8;
  }

  return Huge(sign, size, data);
}

void left_shift(Huge h1) {
  int i;
  int old_carry, carry = 0;

  i = h1.size;
  do {
    i--;
    old_carry = carry;
    carry = (h1.rep[i] & 0x80) == 0x80 ? 1 : 0;
    h1.rep[i] = (h1.rep[i] << 1) | old_carry;
    // Again, if C exposed the overflow bit...
  } while (i != 0);

  if (carry != 0) {
    expand(h1);
  }
}

/**
 * Multiply h1 by h2, overwriting the value of h1.
 */
void multiply(Huge? h1, Huge h2) {
  int mask;
  int i;
  int result_sign;
  Huge temp = set_huge(0);

  copy_huge(temp, h1!);

  result_sign = (h1.sign == h2.sign) ? 0 : 1;

  h1 = set_huge(0);

  i = h2.size;
  do {
    i--;
    for (mask = 0x01; mask != 0; mask <<= 1) {
      if (mask & h2.rep[i] != 0) {
        add(h1, temp);
      }
      left_shift(temp);
    }
  } while (i != 0);

  h1.sign = result_sign;
}

/**
 * Compare h1 to h2. Return:
 * 0 if h1 == h2
 * a positive number if h1 > h2
 * a negative number if h1 < h2
 */
int compare(Huge h1, Huge h2) {
  int i, j;

  if (h1.size > h2.size) {
    return 1;
  }

  if (h1.size < h2.size) {
    return -1;
  }

  // Otherwise, sizes are equal, have to actually compare.
  // only have to compare "hi-int", since the lower ints
  // can't change the comparison.
  i = j = 0;

  // Otherwise, keep searching through the representational integers
  // until one is bigger than another - once we've found one, it's
  // safe to stop, since the "lower order bytes" can't affect the
  // comparison
  while (i < h1.size && j < h2.size) {
    if (h1.rep[i] < h2.rep[j]) {
      return -1;
    } else if (h1.rep[i] > h2.rep[j]) {
      return 1;
    }
    i++;
    j++;
  }

  // If we got all the way to the end without a comparison, the
  // two are equal
  return 0;
}

void right_shift(Huge h1) {
  int i;
  int old_carry, carry = 0;

  i = 0;
  do {
    old_carry = carry;
    carry = (h1.rep[i] & 0x01) << 7;
    h1.rep[i] = (h1.rep[i] >> 1) | old_carry;
  } while (++i < h1.size);

  contract(h1);
}

/**
 * dividend = numerator, divisor = denominator
 *
 * Note that this process destroys divisor (and, of course,
 * overwrites quotient). The dividend is the remainder of the 
 * division (if that's important to the caller). The divisor will 
 * be modified by this routine, but it will end up back where it
 * �started�.
 */
void divide(Huge dividend, Huge divisor, Huge? quotient) {
  int bit_size, bit_position;

  // "bit_position" keeps track of which bit, of the quotient,
  // is being set or cleared on the current operation.
  bit_size = bit_position = 0;

  // First, left-shift divisor until it's >= than the dividend
  while (compare(divisor, dividend) < 0) {
    left_shift(divisor);
    bit_size++;
  }

  // overestimates a bit in some cases
  if (quotient != null) {
    quotient.sign = (dividend.sign == dividend.sign) ? 0 : 1;
    quotient.size = ((bit_size / 8) + 1).toInt();
    quotient.rep = List.filled(quotient.size, 0);
    //   calloc(quotient.size, sizeof( unsigned char ) );
    // memset( quotient.rep, 0, quotient.size );
  }

  bit_position = 8 - (bit_size % 8) - 1;

  do {
    if (compare(divisor, dividend) <= 0) {
      subtract_magnitude(dividend, divisor); // dividend -= divisor
      if (quotient != null) {
        quotient.rep[(bit_position / 8).toInt()] |=
            (0x80 >> (bit_position % 8));
      }
    }

    if (bit_size != 0) {
      right_shift(divisor);
    }
    bit_position++;
  } while (bit_size-- != 0);
}

/**
 * Raise h1 to the power of exp. Return the result in h1.
 */
void exponentiate(Huge h1, Huge exp) {
  int i = exp.size, mask;
  Huge tmp1 = set_huge(0);
  Huge tmp2 = set_huge(0);

  copy_huge(tmp1, h1);
  h1 = set_huge(1);

  do {
    i--;
    for (mask = 0x01; mask != 0; mask <<= 1) {
      if (exp.rep[i] & mask != 0) {
        multiply(h1, tmp1);
      }

      // Square tmp1
      copy_huge(tmp2, tmp1);
      multiply(tmp1, tmp2);
    }
  } while (i != 0);

  // free_huge(tmp1);
  // free_huge(tmp2);
}

/**
 * Compute c = m^e mod n.
 *
 * Note that this same routine is used for encryption and 
 * decryption; the only difference is in the exponent passed in.
 * This is the "exponentiate" algorithm, with the addition of a
 * modulo computation at each stage. 
 */
void mod_pow(Huge h1, Huge exp, Huge n, Huge h2) {
  int i = exp.size;
  int mask;

  Huge tmp1 = set_huge(0);
  Huge tmp2 = set_huge(0);
  copy_huge(tmp1, h1);
  h1 = set_huge(1);

  do {
    i--;
    for (mask = 0x01; mask != 0; mask <<= 1) {
      if (exp.rep[i] & mask != 0) {
        multiply(h2, tmp1);
        divide(h2, n, null);
      }
      // square tmp1
      copy_huge(tmp2, tmp1);
      multiply(tmp1, tmp2);
      divide(tmp1, n, null);
    }
  } while (i != 0);

  // free_huge(tmp1);
  // free_huge(tmp2);

  // Result is now in "h2"
}

void inv(Huge z, Huge a) {
  Huge i, j, y2, y1, y, remainder, a_temp;

  Huge? quotient;

  i = set_huge(1); // initialize for copy
  j = set_huge(1); // initialize for copy
  remainder = set_huge(1); // initialize for copy
  y = set_huge(1);

  a_temp = set_huge(1);

  y2 = set_huge(0);
  y1 = set_huge(1);

  copy_huge(i, a);
  copy_huge(j, z);
  if (z.sign != 0) {
    divide(j, a, null);
    // force positive remainder always
    j.sign = 0;
    subtract(j, a);
  }

  while (((j.size == 1) == 0 && (j.rep[0]) == 0)) {
    copy_huge(remainder, i);
    copy_huge(i, j);
    divide(remainder, j, quotient);

    multiply(quotient, y1); // quotient = y1 * quotient
    copy_huge(y, y2);
    subtract(y, quotient!); // y = y2 - ( y1 * quotient )

    copy_huge(j, remainder);
    copy_huge(y2, y1);
    copy_huge(y1, y);
  }

  copy_huge(z, y2);
  copy_huge(a_temp, a);
  divide(z, a_temp, null); // inv_z = y2 % a

  if (z.sign != 0) {
    z.sign = 0;
    subtract(z, a_temp);
    if (z.sign != 0) {
      z.sign = 0;
    }
  }
}
