import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';

// Secp256k1 parameters
class Secp256k1 {
  static final BigInt p = BigInt.parse(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
      radix: 16);
  static final BigInt a = BigInt.zero;
  static final BigInt b = BigInt.from(7);
  static final BigInt n = BigInt.parse(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
      radix: 16);
  static final BigInt gx = BigInt.parse(
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      radix: 16);
  static final BigInt gy = BigInt.parse(
      '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      radix: 16);
}

// Elliptic Curve Point Representation
class ECPoint {
  final BigInt x;
  final BigInt y;
  final bool isInfinity;

  ECPoint(this.x, this.y) : isInfinity = false;
  ECPoint.infinity()
      : x = BigInt.zero,
        y = BigInt.zero,
        isInfinity = true;

  // Check if two points are equal
  @override
  bool operator ==(Object other) =>
      other is ECPoint &&
      x == other.x &&
      y == other.y &&
      isInfinity == other.isInfinity;

  @override
  int get hashCode => x.hashCode ^ y.hashCode;
}

class ECC {
  static ECPoint add(ECPoint P, ECPoint Q) {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    final p = Secp256k1.p;

    if (P == Q) {
      return doublePoint(P);
    }

    if (P.x == Q.x && (P.y + Q.y) % p == BigInt.zero) {
      return ECPoint.infinity(); // Point at infinity (P + (-P) = 0)
    }

    // Compute lambda = (y2 - y1) / (x2 - x1) mod p
    BigInt lambda = ((Q.y - P.y) * _modInverse(Q.x - P.x, p)) % p;

    // Compute new x, y
    BigInt x3 = (lambda * lambda - P.x - Q.x) % p;
    BigInt y3 = (lambda * (P.x - x3) - P.y) % p;

    return ECPoint(x3, y3);
  }

  static ECPoint doublePoint(ECPoint P) {
    if (P.isInfinity) return P;

    final p = Secp256k1.p;
    final a = Secp256k1.a;

    // Compute lambda = (3x^2 + a) / (2y) mod p
    BigInt lambda = ((BigInt.from(3) * P.x * P.x + a) *
            _modInverse(BigInt.from(2) * P.y, p)) %
        p;

    // Compute new x, y
    BigInt x3 = (lambda * lambda - BigInt.from(2) * P.x) % p;
    BigInt y3 = (lambda * (P.x - x3) - P.y) % p;

    return ECPoint(x3, y3);
  }

  // Compute modular inverse using Extended Euclidean Algorithm
  static BigInt _modInverse(BigInt a, BigInt m) {
    BigInt m0 = m, t, q;
    BigInt x0 = BigInt.zero, x1 = BigInt.one;

    if (m == BigInt.one) return BigInt.zero;

    while (a > BigInt.one) {
      q = a ~/ m;
      t = m;
      m = a % m;
      a = t;
      t = x0;
      x0 = x1 - q * x0;
      x1 = t;
    }

    return x1 % m0;
  }

  static ECPoint multiply(ECPoint P, BigInt k) {
    ECPoint result = ECPoint.infinity();
    ECPoint addend = P;

    while (k > BigInt.zero) {
      if (k & BigInt.one != BigInt.zero) {
        result = add(result, addend);
      }
      addend = doublePoint(addend);
      k >>= 1;
    }
    return result;
  }
}

class KeyPair {
  late BigInt privateKey;
  late ECPoint publicKey;

  KeyPair() {
    final rng = Random.secure();
    final byteLength =
        (Secp256k1.n.bitLength + 7) ~/ 8; // Calculate the byte length for n

    // Generate random bytes for the private key
    final bytes = Uint8List(byteLength);
    for (int i = 0; i < byteLength; i++) {
      bytes[i] = rng.nextInt(256);
    }

    // Convert the bytes to a BigInt and reduce it mod n
    privateKey = BigInt.from(
            bytes.fold<int>(0, (prev, element) => (prev << 8) | element)) %
        Secp256k1.n;

    // Calculate the public key
    publicKey = ECC.multiply(ECPoint(Secp256k1.gx, Secp256k1.gy), privateKey);
  }
}

void main() {
  var keypair = KeyPair();
  print("Private Key: ${keypair.privateKey}");
  print("Public Key: (${keypair.publicKey.x}, ${keypair.publicKey.y})");

  // You can proceed with further steps such as ECDSA signing/verification or ECDH here.
}
