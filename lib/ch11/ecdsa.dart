import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart'; // Import SHA256 from the crypto package

import 'ecc4.dart';

// Hash function for message (SHA-256)
// Secp256k1 parameters and ECC classes stay the same

// Hash function for message (SHA-256)
BigInt _hashMessage(String message) {
  final bytes = utf8.encode(message);
  final hash = sha256.convert(bytes);
  return BigInt.parse(hash.toString(), radix: 16);
}

// ECDSA Signing
// ECDSA Signing and Verification Updates
class ECDSA {
  static List<BigInt> sign(String message, BigInt privateKey) {
    BigInt z = _hashMessage(message); // Hash the message

    // Generate random k
    final rng = Random.secure();
    BigInt k;
    do {
      k = BigInt.from(rng.nextInt(1 << 30)) % Secp256k1.n;
    } while (k == BigInt.zero);

    // Calculate r = x-coordinate(k * G) mod n
    ECPoint kG = ECC.multiply(ECPoint(Secp256k1.gx, Secp256k1.gy), k);
    BigInt r = kG.x % Secp256k1.n;
    if (r == BigInt.zero) return sign(message, privateKey); // Retry if r == 0

    // Calculate s = k^-1 * (z + r * d) mod n
    BigInt s =
        ((k.modInverse(Secp256k1.n) * (z + r * privateKey)) % Secp256k1.n);
    if (s == BigInt.zero) return sign(message, privateKey); // Retry if s == 0

    return [r, s];
  }

  static bool verify(
      String message, List<BigInt> signature, ECPoint publicKey) {
    BigInt r = signature[0];
    BigInt s = signature[1];

    // Ensure valid signature
    if (r <= BigInt.zero ||
        r >= Secp256k1.n ||
        s <= BigInt.zero ||
        s >= Secp256k1.n) {
      return false; // Invalid signature
    }

    // Hash the message
    BigInt z = _hashMessage(message);

    // Calculate w = s^-1 mod n
    BigInt w = s.modInverse(Secp256k1.n);

    // Calculate v = w * z mod n
    BigInt v = (w * z) % Secp256k1.n;

    // Calculate w * r mod n
    BigInt wR = (w * r) % Secp256k1.n;

    // Calculate P = v * G + wR * publicKey
    ECPoint P = ECC.add(ECC.multiply(ECPoint(Secp256k1.gx, Secp256k1.gy), v),
        ECC.multiply(publicKey, wR));

    // Final verification of r = x(P) mod n
    return P.x % Secp256k1.n == r;
  }
}

class ECDH {
  // Generate shared secret
  static BigInt generateSharedSecret(
      BigInt privateKey, ECPoint otherPublicKey) {
    // Multiply the other party's public key by our private key
    ECPoint sharedPoint = ECC.multiply(otherPublicKey, privateKey);
    return sharedPoint.x; // Return the x-coordinate as the shared secret
  }
}

void main() {
  // Generate ECDSA keys
  var keypair = KeyPair();
  print("Private Key: ${keypair.privateKey}");
  print("Public Key: (${keypair.publicKey.x}, ${keypair.publicKey.y})");

  // Signing a message
  String message = "Hello, ECDSA!";
  List<BigInt> signature = ECDSA.sign(message, keypair.privateKey);
  print("Signature: r = ${signature[0]}, s = ${signature[1]}");

  // Verifying the signature
  bool isValid = ECDSA.verify(message, signature, keypair.publicKey);
  print("Signature valid? $isValid");

  // ECDH: Key exchange between two parties
  var keypair1 = KeyPair();
  var keypair2 = KeyPair();

  // Both parties generate the shared secret using each other's public keys
  BigInt sharedSecret1 =
      ECDH.generateSharedSecret(keypair1.privateKey, keypair2.publicKey);
  BigInt sharedSecret2 =
      ECDH.generateSharedSecret(keypair2.privateKey, keypair1.publicKey);

  print("Shared secret (Party 1): $sharedSecret1");
  print("Shared secret (Party 2): $sharedSecret2");

  // Verify the shared secrets match
  print("Do the shared secrets match? ${sharedSecret1 == sharedSecret2}");
}
