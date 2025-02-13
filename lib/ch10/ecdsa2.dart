import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'sha256.dart';

// P-256 (secp256r1) Curve Parameters
class CurveP256 {
  static final BigInt p = BigInt.parse(
      '0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
  static final BigInt n = BigInt.parse(
      '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  static final BigInt a = BigInt.from(-3);
  static final BigInt b = BigInt.parse(
      '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
  static final BigInt Gx = BigInt.parse(
      '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
  static final BigInt Gy = BigInt.parse(
      '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162cbdfd238d4b8dde6c3aeda4b18b7f36');
}

// Elliptic Curve Point
class ECPoint {
  final BigInt x, y;
  final bool isInfinity;

  ECPoint(this.x, this.y) : isInfinity = false;
  ECPoint.infinity()
      : x = BigInt.zero,
        y = BigInt.zero,
        isInfinity = true;

  @override
  String toString() => isInfinity ? "Infinity" : "($x, $y)";
}

// Modular Inverse (Extended Euclidean Algorithm)
BigInt modInverse(BigInt a, BigInt m) {
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

  return x1 < BigInt.zero ? x1 + m0 : x1;
}

// Point Addition
ECPoint ecAdd(ECPoint P, ECPoint Q, BigInt p) {
  if (P.isInfinity) return Q;
  if (Q.isInfinity) return P;

  if (P.x == Q.x) {
    if (P.y != Q.y || P.y == BigInt.zero) return ECPoint.infinity();
    return ecDouble(P, p);
  }

  BigInt lambda = ((Q.y - P.y) * modInverse(Q.x - P.x, p)) % p;
  BigInt xR = (lambda * lambda - P.x - Q.x) % p;
  BigInt yR = (lambda * (P.x - xR) - P.y) % p;

  return ECPoint(xR, yR);
}

// Point Doubling
ECPoint ecDouble(ECPoint P, BigInt p) {
  if (P.isInfinity) return P;

  BigInt lambda = ((BigInt.from(3) * P.x * P.x + CurveP256.a) *
          modInverse(BigInt.from(2) * P.y, p)) %
      p;
  BigInt xR = (lambda * lambda - BigInt.from(2) * P.x) % p;
  BigInt yR = (lambda * (P.x - xR) - P.y) % p;

  return ECPoint(xR, yR);
}

// Scalar Multiplication
ECPoint ecMul(BigInt d, ECPoint P, BigInt p) {
  ECPoint result = ECPoint.infinity();
  ECPoint addend = P;

  while (d > BigInt.zero) {
    if (d.isOdd) result = ecAdd(result, addend, p);
    addend = ecDouble(addend, p);
    d >>= 1;
  }

  return result;
}

// Generate Private Key
BigInt generatePrivateKey() {
  BigInt d;
  do {
    d = generateSecureBigInt(CurveP256.n);
  } while (d < BigInt.one || d >= CurveP256.n); // Ensure 1 ≤ d < n
  return d;
}

// Generate ECDSA Key Pair
Map<String, dynamic> generateKeyPair() {
  BigInt privateKey = generatePrivateKey();
  ECPoint publicKey =
      ecMul(privateKey, ECPoint(CurveP256.Gx, CurveP256.Gy), CurveP256.p);

  return {
    "privateKey": privateKey,
    "publicKey": publicKey,
  };
}

// Sign a Message
Map<String, BigInt> signMessage(BigInt messageHash, BigInt privateKey) {
  final rand = Random.secure();
  BigInt r = BigInt.zero, s = BigInt.zero, k = BigInt.zero;

  while (r == BigInt.zero || s == BigInt.zero) {
    // Generate random k within the range [1, n-1]
    k = generateSecureBigInt(CurveP256.n);

    // Ensure k is in the valid range (1 ≤ k < n)
    if (k <= BigInt.zero || k >= CurveP256.n) continue;

    ECPoint R = ecMul(k, ECPoint(CurveP256.Gx, CurveP256.Gy), CurveP256.p);
    r = R.x % CurveP256.n;

    if (r == BigInt.zero) continue;

    s = ((messageHash + r * privateKey) * modInverse(k, CurveP256.n)) %
        CurveP256.n;
  }

  return {'r': r, 's': s};
}

// Verify Signature
bool verifySignature(
    BigInt messageHash, Map<String, BigInt> signature, ECPoint publicKey) {
  BigInt r = signature['r']!;
  BigInt s = signature['s']!;
  if (r <= BigInt.zero ||
      r >= CurveP256.n ||
      s <= BigInt.zero ||
      s >= CurveP256.n) return false;

  BigInt w = modInverse(s, CurveP256.n);
  BigInt u1 = (messageHash * w) % CurveP256.n;
  BigInt u2 = (r * w) % CurveP256.n;

  ECPoint P1 = ecMul(u1, ECPoint(CurveP256.Gx, CurveP256.Gy), CurveP256.p);
  ECPoint P2 = ecMul(u2, publicKey, CurveP256.p);
  ECPoint P = ecAdd(P1, P2, CurveP256.p);

  return P.x % CurveP256.n == r;
}

// Secure Random BigInt Generator
BigInt generateSecureBigInt(BigInt max) {
  final rand = Random.secure();
  final bytes = Uint8List((max.bitLength + 7) >> 3); // Convert bits to bytes
  BigInt result;

  do {
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = rand.nextInt(256);
    }
    result = BigInt.parse(
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        radix: 16);
  } while (result <= BigInt.one || result >= max);

  return result;
}

// Example Usage
void main() {
  // Generate Key Pair
  var keyPair = generateKeyPair();
  BigInt privateKey = keyPair['privateKey'];
  ECPoint publicKey = keyPair['publicKey'];

  print("Private Key: $privateKey");
  print("Public Key: $publicKey");

  // Hash message (for simplicity, just using a fixed value)
  BigInt messageHash = BigInt.parse("123456789abcdef", radix: 16);
  Uint8List hash = sha256Hash(utf8.encode("123456789abcdef"));
  // Sign the message
  var signature = signMessage(messageHash, privateKey);
  print("Signature: r=${signature['r']}, s=${signature['s']}");

  // Verify the signature
  bool isValid = verifySignature(messageHash, signature, publicKey);
  print("Signature Valid: $isValid");
}
