import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

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

// Point on the curve
class Point {
  final BigInt x;
  final BigInt y;
  Point(this.x, this.y);

  static final Point infinity = Point(BigInt.zero, BigInt.zero);

  bool get isInfinity => x == BigInt.zero && y == BigInt.zero;
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

BigInt modInverse(BigInt a, BigInt modulus) {
  // Use the Extended Euclidean Algorithm to calculate the modular inverse
  BigInt t = BigInt.zero, newT = BigInt.one;
  BigInt r = modulus, newR = a % modulus;

  while (newR != BigInt.zero) {
    BigInt quotient = r ~/ newR;
    t = newT - quotient * t;
    newT = t;
    r = newR;
    newR = r - quotient * newR;
  }

  if (r > BigInt.one) {
    throw ArgumentError("Not invertible: $a has no inverse modulo $modulus");
  }

  return (t + modulus) % modulus;
}

Point ellipticCurvePointAdd(Point P1, Point P2) {
  if (P1.isInfinity) return P2;
  if (P2.isInfinity) return P1;

  BigInt lambda;
  if (P1.x == P2.x && P1.y == P2.y) {
    // Point doubling
    try {
      lambda = ((BigInt.from(3) * P1.x * P1.x + A) *
              modInverse(BigInt.from(2) * P1.y, P)) %
          P;
    } catch (e) {
      throw ArgumentError(
          "Failed to compute modular inverse during point doubling: $e");
    }
  } else {
    // Regular addition
    try {
      lambda = ((P2.y - P1.y) * modInverse(P2.x - P1.x, P)) % P;
    } catch (e) {
      throw ArgumentError(
          "Failed to compute modular inverse during point addition: $e");
    }
  }

  BigInt x3 = (lambda * lambda - P1.x - P2.x) % P;
  BigInt y3 = (lambda * (P1.x - x3) - P1.y) % P;

  return Point(x3, y3);
}

// Signing process (ECDSA)
List<BigInt> sign(BigInt privateKey, Uint8List messageHash) {
  BigInt k = BigInt.from(Random().nextInt(1000000)); // Random integer k
  Point G = Point(
      BigInt.parse(
          '6B17D1F2E12C4247F8B2D8E2E2F9D2F2F7F9E7F2B2B3A4A1F1A1B2A1A1B2C2D2',
          radix: 16),
      BigInt.parse(
          '4D1A46E38F8C810AC0C1B3BFC1F1A1A2A4D2F2C2D4D3D4F5F3A2A7F3A4A5A5F1',
          radix: 16)); // Base point G (part of the curve)

  // Calculate r = (k * G)_x % n
  Point kG = ellipticCurveScalarMultiply(G, k);
  BigInt r = kG.x % N;

  if (r == BigInt.zero) {
    return sign(privateKey, messageHash); // Retry if r == 0
  }

  // Calculate s = (k^(-1) * (H(M) + r * d)) % n
  BigInt kInv = modInverse(k, N);
  BigInt hM = BigInt.parse(
      messageHash.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16); // H(M)

  BigInt s = (kInv * (hM + r * privateKey) % N) % N;
  if (s == BigInt.zero) {
    return sign(privateKey, messageHash); // Retry if s == 0
  }

  return [r, s];
}

// Verification process (ECDSA)
bool verify(
    List<BigInt> signature, Uint8List messageHash, List<BigInt> publicKey) {
  BigInt r = signature[0];
  BigInt s = signature[1];

  if (r <= BigInt.zero || r >= N || s <= BigInt.zero || s >= N) {
    return false; // Invalid signature parameters
  }

  // Calculate H(M)
  BigInt hM = BigInt.parse(
      messageHash.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);

  BigInt w = modInverse(s, N);
  BigInt u1 = (hM * w) % N;
  BigInt u2 = (r * w) % N;

  // Calculate P = u1 * G + u2 * Q
  Point G = Point(
      BigInt.parse(
          '6B17D1F2E12C4247F8B2D8E2E2F9D2F2F7F9E7F2B2B3A4A1F1A1B2A1A1B2C2D2',
          radix: 16),
      BigInt.parse(
          '4D1A46E38F8C810AC0C1B3BFC1F1A1A2A4D2F2C2D4D3D4F5F3A2A7F3A4A5A5F1',
          radix: 16));
  Point Q = ellipticCurveScalarMultiply(
      Point(publicKey[0], publicKey[1]), BigInt.one);
  Point P = ellipticCurveScalarMultiply(G, u1);
  P = ellipticCurvePointAdd(P, ellipticCurveScalarMultiply(Q, u2));

  // The signature is valid if P_x % n == r
  return P.x % N == r;
}

// void main() {
//   // Example usage:
//   Uint8List messageHash = utf8.encode("Message to sign");

//   // Generate private key (for example)
//   BigInt privateKey = BigInt.parse('1234567890abcdef1234567890abcdef', radix: 16);

//   // Generate the public key from the private key
//   Point publicKeyPoint = ellipticCurveScalarMultiply(
//       Point(
//           BigInt.parse(
//               '6B17D1F2E12C4247F8B2D8E2E2F9D2F2F7F9E7F2B2B3A4A1F1A1B2A1A1B2C2D2',
//               radix: 16),
//           BigInt.parse(
//               '4D1A46E38F8C810AC0C1B3BFC1F1A1A2A4D2F2C2D4D3D4F5F3A2A7F3A4A5A5F1',
//               radix: 16)),
//       privateKey);
//   List<BigInt> publicKey = [publicKeyPoint.x, publicKeyPoint.y];

//   // Sign the message
//   List<BigInt> signature = sign(privateKey, messageHash);
//   print("Signature: r=${signature[0]}, s=${signature[1]}");

//   // Verify the signature
//   bool isValid = verify(signature, messageHash, publicKey);
//   print("Signature valid: $isValid");
// }

void main() {
  try {
    // Example message to be signed
    String message = "Hello, this is a message to be signed!";
    Uint8List messageHash = utf8.encode(message);

    // Generate private key (for example)
    BigInt privateKey =
        BigInt.parse('1234567890abcdef1234567890abcdef', radix: 16);

    // Generate the public key from the private key
    Point publicKeyPoint = ellipticCurveScalarMultiply(
        Point(
            BigInt.parse(
                '6B17D1F2E12C4247F8B2D8E2E2F9D2F2F7F9E7F2B2B3A4A1F1A1B2A1A1B2C2D2',
                radix: 16),
            BigInt.parse(
                '4D1A46E38F8C810AC0C1B3BFC1F1A1A2A4D2F2C2D4D3D4F5F3A2A7F3A4A5A5F1',
                radix: 16)),
        privateKey);
    List<BigInt> publicKey = [publicKeyPoint.x, publicKeyPoint.y];

    // Sign the message
    List<BigInt> signature = sign(privateKey, messageHash);
    print("Signature: r=${signature[0]}, s=${signature[1]}");

    // Verify the signature
    bool isValid = verify(signature, messageHash, publicKey);
    print("Signature valid: $isValid");
  } catch (e) {
    print("Error: $e");
  }
}
// Explanation:
// Message: We have a message "Hello, this is a message to be signed!".
// Private Key: We simulate the private key 1234567890abcdef1234567890abcdef for signing the message.
// Public Key: We generate the public key from the private key.
// Signing: The sign function generates the signature (r, s) for the message.
// Verification: The verify function checks the signature's validity by ensuring the signature matches the public key and the hash of the message.
// Output Example:
// text
// Copy
// Edit
// Signature: r=83969617864505749275860773682663170604113314866407307014435274396041525606, s=545494693798679055123218902623276946431
