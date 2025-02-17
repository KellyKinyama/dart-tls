import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart'; // import for SHA256

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
    privateKey = BigInt.from(rng.nextInt(1 << 30)) % Secp256k1.n;
    publicKey = ECC.multiply(ECPoint(Secp256k1.gx, Secp256k1.gy), privateKey);
  }
}

class ECDSA {
  static List<BigInt> sign(BigInt privateKey, Uint8List message) {
    final n = Secp256k1.n;
    final rng = Random.secure();

    // 1. Hash the message (using SHA256)
    var messageHash = _sha256(message);

    // 2. Generate a random integer k in [1, n-1]
    BigInt k = _generateRandomBigInt(n);

    // 3. Compute r = (k * G).x % n
    ECPoint kG = ECC.multiply(ECPoint(Secp256k1.gx, Secp256k1.gy), k);
    BigInt r = kG.x % n;

    // If r == 0, retry
    if (r == BigInt.zero) {
      return sign(privateKey, message);
    }

    // 4. Compute s = (r * privateKey + k * messageHash) % n
    BigInt s = ((r * privateKey + k * messageHash) % n);

    // If s == 0, retry
    if (s == BigInt.zero) {
      return sign(privateKey, message);
    }

    return [r, s];
  }

  static BigInt _generateRandomBigInt(BigInt upperBound) {
    final rng = Random.secure();
    final byteLength = (upperBound.bitLength + 7) ~/ 8;
    final bytes = Uint8List(byteLength);
    for (int i = 0; i < byteLength; i++) {
      bytes[i] = rng.nextInt(256);
    }
    BigInt k = BigInt.from(
        bytes.fold<int>(0, (prev, element) => (prev << 8) | element));
    return k % upperBound;
  }

  static bool verify(
      ECPoint publicKey, Uint8List message, List<BigInt> signature) {
    final n = Secp256k1.n;
    final p = Secp256k1.p;

    BigInt r = signature[0];
    BigInt s = signature[1];

    // 1. Hash the message (using SHA256)
    var messageHash = _sha256(message);

    // 2. Compute w = s^(-1) mod n
    BigInt w = ECC._modInverse(s, n);

    // 3. Compute u1 = messageHash * w % n and u2 = r * w % n
    BigInt u1 = (messageHash * w) % n;
    BigInt u2 = (r * w) % n;

    // 4. Compute P = (u1 * G + u2 * publicKey)
    ECPoint P = ECPoint.infinity();
    P = ECC.add(P, ECC.multiply(ECPoint(Secp256k1.gx, Secp256k1.gy), u1));
    P = ECC.add(P, ECC.multiply(publicKey, u2));

    // 5. If P == O (point at infinity), signature is invalid
    if (P.isInfinity) {
      return false;
    }

    // 6. Verify r == P.x % n
    return r == P.x % n;
  }

  static BigInt _sha256(Uint8List data) {
    return BigInt.parse(sha256.convert(data).toString(), radix: 16);
  }
}

void main() {
  // Generate keypair
  var keypair = KeyPair();
  print("Private Key: ${keypair.privateKey}");
  print("Public Key: (${keypair.publicKey.x}, ${keypair.publicKey.y})");

  // Create a message and sign it
  String message = "Hello, ECDSA!";
  var signature =
      ECDSA.sign(keypair.privateKey, Uint8List.fromList(message.codeUnits));
  print("Signature: r = ${signature[0]}, s = ${signature[1]}");

  // Verify the signature
  bool valid = ECDSA.verify(
      keypair.publicKey, Uint8List.fromList(message.codeUnits), signature);
  print("Signature valid? $valid");
}
