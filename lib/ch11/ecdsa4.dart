import 'dart:math';
import 'dart:typed_data';

class ECDSAVerification {
  // SECP256k1 curve parameters
  static const BigInt p = BigInt.parse(
      '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'); // Curve prime
  static const BigInt a = BigInt.zero; // a coefficient for secp256k1
  static const BigInt b = BigInt.from(7); // b coefficient for secp256k1
  static const BigInt n = BigInt.parse(
      '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'); // Order of the base point

  // This is the generator point G for secp256k1 (x, y coordinates)
  static const BigInt Gx = BigInt.parse(
      '0x79BE667EF9DCBBAC55A62F22D6C34C3E27D2604B9B8D5A9D3A8C3A6A87C1B2A9B8');
  static const BigInt Gy = BigInt.parse(
      '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A3D81E3C6FEDD1DEDBF3C9A2');

  // Function to calculate modular inverse
  static BigInt modInverse(BigInt a, BigInt m) {
    BigInt t = BigInt.zero, newT = BigInt.one;
    BigInt r = m, newR = a;
    while (newR != BigInt.zero) {
      BigInt quotient = r ~/ newR;
      t = t - quotient * newT;
      r = r - quotient * newR;
      if (t < BigInt.zero) t = t + m;
      if (r < BigInt.zero) r = r + m;
      var temp = t;
      t = newT;
      newT = temp;
      temp = r;
      r = newR;
      newR = temp;
    }
    if (r > BigInt.one) {
      throw 'No modular inverse found';
    }
    if (t < BigInt.zero) {
      t = t + m;
    }
    return t;
  }

  // Perform elliptic curve point multiplication
  static BigInt pointMultiply(BigInt k, BigInt x, BigInt y) {
    BigInt x0 = x, y0 = y;
    BigInt z0 = BigInt.one;
    BigInt z = BigInt.zero;
    int i = 255;

    while (i >= 0) {
      BigInt lambda = (x0 * y0) % p;
      lambda = (lambda * z) % p;
      BigInt newX = (x0 * y) % p;
      BigInt newY = (y0 * x) % p;
      x0 = newX;
      y0 = newY;
      z = lambda;
      i--;
    }
    return x0;
  }

  // ECDSA Verification
  static bool verify(BigInt r, BigInt s, BigInt messageHash, BigInt publicKeyX, BigInt publicKeyY) {
    if (r <= BigInt.zero || r >= n || s <= BigInt.zero || s >= n) {
      return false;
    }

    // Calculate w = s^-1 mod n
    BigInt w = modInverse(s, n);

    // Calculate u1 = (messageHash * w) mod n, u2 = (r * w) mod n
    BigInt u1 = (messageHash * w) % n;
    BigInt u2 = (r * w) % n;

    // Calculate the elliptic curve point P = u1 * G + u2 * publicKey
    BigInt x = pointMultiply(u1, Gx, Gy); // u1 * G
    BigInt y = pointMultiply(u2, publicKeyX, publicKeyY); // u2 * publicKey

    // Add the two points
    BigInt finalX = (x + y) % p;

    // Verify the signature
    print("Message Hash for verification: $messageHash");
    print("Computed P: x = $finalX, y = ?");

    // Check if the point is on the curve
    BigInt left = (finalX * finalX * finalX + b) % p;
    BigInt right = (finalX * finalX) % p;

    print("Curve check: left = $left, right = $right");

    if (left == right) {
      print("Point is on the curve");
    } else {
      print("Point is NOT on the curve");
    }

    return finalX == r;
  }
}

void main() {
  BigInt privateKey = BigInt.from(402480545); // Example private key
  BigInt messageHash = BigInt.from(47251298420149935885156812592629867927474418964758231288704275995193241016010); // Example message hash

  // Generate the public key from private key
  BigInt publicKeyX = ECDSAVerification.Gx * privateKey;
  BigInt publicKeyY = ECDSAVerification.Gy * privateKey;

  // Example signature
  BigInt r = BigInt.from(10408906418412977576656081324976560275468927829099588073104656251893941774986);
  BigInt s = BigInt.from(66348567343389319256454804151962237687304516014019065564985623108903802782554);

  // Verify the signature
  bool isValid = ECDSAVerification.verify(r, s, messageHash, publicKeyX, publicKeyY);
  print('Signature valid? $isValid');
}
