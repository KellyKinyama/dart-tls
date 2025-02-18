import 'dart:typed_data';

// This function computes the shared secret key using elliptic curve point multiplication.
// Assumes that you have an ECC library to perform the actual point operations (e.g., elliptic curve addition and multiplication).
BigInt computeSharedKey(BigInt receivedPublicKeyX, BigInt receivedPublicKeyY,
    BigInt privateKey, BigInt P, BigInt A, BigInt B, BigInt N) {
  // Initialize the point (Gx, Gy) from the received public key
  Point receivedPublicKey = Point(receivedPublicKeyX, receivedPublicKeyY);

  // Perform scalar multiplication: privateKey * receivedPublicKey
  // Scalar multiplication is performed using elliptic curve point doubling and addition
  Point sharedSecretPoint =
      ellipticCurveScalarMultiply(receivedPublicKey, privateKey, P, A, B, N);

  // Return the x-coordinate of the resulting point as the shared secret key
  return sharedSecretPoint.x;
}

// Elliptic curve point multiplication (scalar multiplication)
Point ellipticCurveScalarMultiply(
    Point point, BigInt scalar, BigInt P, BigInt A, BigInt B, BigInt N) {
  Point result = Point(BigInt.zero, BigInt.zero); // Identity point (0, 0)
  Point basePoint = point;

  // Perform the "double-and-add" method for scalar multiplication
  while (scalar > BigInt.zero) {
    if (scalar.isOdd) {
      result = ellipticCurvePointAdd(
          result, basePoint, P, A, B); // Add basePoint to result
    }
    basePoint = ellipticCurvePointAdd(
        basePoint, basePoint, P, A, B); // Double the base point
    scalar = scalar ~/ BigInt.two; // Divide scalar by 2
  }
  return result;
}

BigInt modInverse(BigInt a, BigInt modulus) {
  // Calculate the modular inverse of 'a' under 'modulus' using the Extended Euclidean Algorithm
  BigInt t = BigInt.zero;
  BigInt newT = BigInt.one;
  BigInt r = modulus;
  BigInt newR = a % modulus;

  while (newR != BigInt.zero) {
    BigInt quotient = r ~/ newR;
    BigInt tempT = t;
    t = newT;
    newT = tempT - quotient * newT;
    BigInt tempR = r;
    r = newR;
    newR = tempR - quotient * newR;
  }

  if (r > BigInt.one) {
    throw ArgumentError("Not coprime");
  }

  if (t < BigInt.zero) {
    t = t + modulus;
  }

  return t;
}

// Elliptic curve point addition
// ignore: non_constant_identifier_names
Point ellipticCurvePointAdd(Point P1, Point P2, BigInt P, BigInt A, BigInt B) {
  // Identity check: if one point is the identity element (0, 0), return the other point
  if (P1 == Point(BigInt.zero, BigInt.zero)) return P2;
  if (P2 == Point(BigInt.zero, BigInt.zero)) return P1;

  BigInt deltaX = (P2.x - P1.x) % P;
  BigInt deltaY = (P2.y - P1.y) % P;

  // Handle the case when deltaX is 0. This could indicate a vertical line or point doubling.
  if (deltaX == BigInt.zero) {
    if (P1 == P2) {
      // Point doubling case: use the point doubling formula
      BigInt lambda = (BigInt.from(3) * P1.x * P1.x + A) *
          modInverse(BigInt.from(2) * P1.y, P) %
          P;
      BigInt x3 = (lambda * lambda - P1.x - P2.x) % P;
      BigInt y3 = (lambda * (P1.x - x3) - P1.y) % P;
      return Point(x3, y3);
    } else {
      throw ArgumentError(
          "Not coprime: the difference in x-coordinates is not coprime with P");
    }
  }

  // Regular point addition case
  BigInt lambda;
  try {
    lambda = deltaY * modInverse(deltaX, P) % P; // Calculate slope (lambda)
  } catch (e) {
    throw ArgumentError("Modular inverse calculation failed: $e");
  }

  BigInt x3 = (lambda * lambda - P1.x - P2.x) % P;
  BigInt y3 = (lambda * (P1.x - x3) - P1.y) % P;

  return Point(x3, y3);
}

// Helper class to represent a point on the elliptic curve
class Point {
  BigInt x;
  BigInt y;

  Point(this.x, this.y);
}

BigInt privateKeyFromUint8List(Uint8List data) {
  // Ensure the data is not empty
  if (data.isEmpty) {
    throw ArgumentError("Private key data cannot be empty");
  }

  // Convert the Uint8List to a hexadecimal string
  String hexString =
      data.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  // Parse the hexadecimal string to BigInt
  return BigInt.parse(hexString, radix: 16);
}

// Convert Uint8List to public key (uncompressed format)
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

Uint8List generateP256SharedSecret(Uint8List publicKey, Uint8List privateKey) {
  BigInt P = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);
  BigInt A = BigInt.zero; // secp256k1 curve A coefficient is 0
  BigInt B = BigInt.parse('7', radix: 16); // secp256k1 curve B coefficient
  BigInt N = BigInt.parse(
      'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
      radix: 16); // Curve order

  final alicePublicKey = publicKeyFromUint8List(publicKey);
  final b = privateKeyFromUint8List(privateKey);

  // Compute the shared secret
  BigInt sharedKey =
      computeSharedKey(alicePublicKey[0], alicePublicKey[1], b, P, A, B, N);

  // Convert the BigInt to a hexadecimal string
  String hexSharedKey =
      sharedKey.toRadixString(16).padLeft(64, '0'); // Ensure even length

  // Convert the hexadecimal string to a byte array (Uint8List)
  return Uint8List.fromList(
    List.generate(hexSharedKey.length ~/ 2, (i) {
      return int.parse(hexSharedKey.substring(i * 2, i * 2 + 2), radix: 16);
    }),
  );
}
