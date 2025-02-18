import 'dart:typed_data';

// P-256 curve parameters
final BigInt P = BigInt.parse(
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
    radix: 16);
final BigInt A = BigInt.from(-3);
final BigInt B = BigInt.parse(
    '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
    radix: 16);
final BigInt N = BigInt.parse(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
    radix: 16);

// Represents a point on the elliptic curve
class Point {
  final BigInt x;
  final BigInt y;
  Point(this.x, this.y);

  static final Point infinity = Point(BigInt.zero, BigInt.zero);

  bool get isInfinity => x == BigInt.zero && y == BigInt.zero;
}

// Compute shared key using scalar multiplication
BigInt computeSharedKey(
    BigInt receivedPublicKeyX, BigInt receivedPublicKeyY, BigInt privateKey) {
  Point receivedPublicKey = Point(receivedPublicKeyX, receivedPublicKeyY);
  Point sharedSecretPoint =
      ellipticCurveScalarMultiply(receivedPublicKey, privateKey);
  return sharedSecretPoint.x;
}

// Scalar multiplication (double-and-add method)
Point ellipticCurveScalarMultiply(Point point, BigInt scalar) {
  Point result = Point.infinity;
  Point basePoint = point;

  while (scalar > BigInt.zero) {
    if (scalar.isOdd) {
      result = ellipticCurvePointAdd(result, basePoint);
    }
    basePoint = ellipticCurvePointAdd(basePoint, basePoint);
    scalar = scalar ~/ BigInt.two;
  }
  return result;
}

// Modular inverse using Extended Euclidean Algorithm
BigInt modInverse(BigInt a, BigInt modulus) {
  BigInt t = BigInt.zero, newT = BigInt.one;
  BigInt r = modulus, newR = a % modulus;

  while (newR != BigInt.zero) {
    BigInt quotient = r ~/ newR;
    t = newT - quotient * t;
    newT = t;
    r = newR;
    newR = r - quotient * newR;
  }

  if (r > BigInt.one) throw ArgumentError("Not invertible");
  return (t + modulus) % modulus;
}

// Elliptic curve point addition
Point ellipticCurvePointAdd(Point P1, Point P2) {
  if (P1.isInfinity) return P2;
  if (P2.isInfinity) return P1;

  BigInt lambda;
  if (P1.x == P2.x && P1.y == P2.y) {
    // Point doubling
    lambda = ((BigInt.from(3) * P1.x * P1.x + A) *
            modInverse(BigInt.from(2) * P1.y, P)) %
        P;
  } else {
    // Regular addition
    lambda = ((P2.y - P1.y) * modInverse(P2.x - P1.x, P)) % P;
  }

  BigInt x3 = (lambda * lambda - P1.x - P2.x) % P;
  BigInt y3 = (lambda * (P1.x - x3) - P1.y) % P;

  return Point(x3, y3);
}

// Convert Uint8List to BigInt (private key)
BigInt privateKeyFromUint8List(Uint8List data) {
  if (data.isEmpty) throw ArgumentError("Private key data cannot be empty");
  return BigInt.parse(
      data.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
}

// Convert Uint8List to public key (x, y)
List<BigInt> publicKeyFromUint8List(Uint8List data) {
  if (data.length != 65 || data[0] != 0x04) {
    throw ArgumentError("Invalid uncompressed public key format");
  }
  BigInt x = BigInt.parse(
      data
          .sublist(1, 33)
          .map((e) => e.toRadixString(16).padLeft(2, '0'))
          .join(),
      radix: 16);
  BigInt y = BigInt.parse(
      data
          .sublist(33, 65)
          .map((e) => e.toRadixString(16).padLeft(2, '0'))
          .join(),
      radix: 16);
  return [x, y];
}

// Generate P-256 shared secret
Uint8List generateP256SharedSecret(Uint8List publicKey, Uint8List privateKey) {
  final alicePublicKey = publicKeyFromUint8List(publicKey);
  final b = privateKeyFromUint8List(privateKey);

  BigInt sharedKey = computeSharedKey(alicePublicKey[0], alicePublicKey[1], b);

  String hexSharedKey = sharedKey.toRadixString(16).padLeft(64, '0');
  return Uint8List.fromList(List.generate(32, (i) {
    return int.parse(hexSharedKey.substring(i * 2, i * 2 + 2), radix: 16);
  }));
}
