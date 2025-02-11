void main() {
  var bigInteger = BigInt.from(-1); // -1
  var bigInteger1 = BigInt.from(0.9999); // 0
  var bigInteger2 = BigInt.from(-10.99); // -10
  var bigInteger3 = BigInt.from(0x7FFFFFFFFFFFFFFF); // 9223372036854775807
  var bigInteger4 = BigInt.from(1e+30); // 1000000000000000019884624838656

  var c = bigInteger + bigInteger1;
  c = bigInteger * bigInteger1;
  c = bigInteger - bigInteger1;
  c = bigInteger / bigInteger1;
  c = bigInteger.pow(exponent, modulus) + bigInteger1;
}
