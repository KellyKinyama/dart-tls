// The code implements a basic Diffie-Hellman key exchange using elliptic curve cryptography (ECC). Here's a breakdown of how it works:

// Power function:

// The function power(a, b, P) calculates
// 𝑎
// 𝑏
// m
// o
// d
//
//
// 𝑃
// a
// b
//  modP. It's used throughout the code to perform modular exponentiation, which is essential in generating public keys and computing shared secret keys.
// modPow() is a method in Dart’s BigInt class that efficiently calculates modular exponentiation.
// Public Key Generation:

// The function generatePublicKey(privateKey, Gx, Gy, P) generates the public key by computing
// 𝐺
// 𝑎
// m
// o
// d
//
//
// 𝑃
// G
// a
//  modP (or
// 𝐺
// 𝑏
// m
// o
// d
//
//
// 𝑃
// G
// b
//  modP for Bob) using the private key and the generator point
// 𝐺
// =
// (
// 𝐺
// 𝑥
// ,
// 𝐺
// 𝑦
// )
// G=(Gx,Gy).
// The generator point
// 𝐺
// G is a fixed point on the elliptic curve, and the public key is derived by multiplying the generator by the private key.
// Shared Secret Computation:

// The function computeSharedKey(receivedPublicKey, privateKey, P) computes the shared secret by using the other party's public key and your private key.
// It computes the elliptic curve multiplication, which allows both Alice and Bob to independently derive the same shared secret.
// Public Key Parsing (Uncompressed Format):

// The function publicKeyFromUint8List(data) converts a raw Uint8List containing an uncompressed public key into two BigInt values representing the x and y coordinates of the elliptic curve point.
// The uncompressed format starts with the byte 0x04 followed by 32 bytes for the x-coordinate and 32 bytes for the y-coordinate.
// Main Logic:

// The main function defines the curve parameters: a large prime
// 𝑃
// P, and the elliptic curve base point
// 𝐺
// =
// (
// 𝐺
// 𝑥
// ,
// 𝐺
// 𝑦
// )
// G=(Gx,Gy).
// Alice and Bob each have their private keys
// 𝑎
// a and
// 𝑏
// b, respectively. From their private keys, they compute their public keys.
// Then, they exchange public keys and compute the shared secret using the other's public key and their own private key.
// Since the Diffie-Hellman exchange is symmetric, both Alice and Bob end up with the same shared secret.
// Example Output:
// The generator point
// 𝐺
// G is printed in hexadecimal.
// Alice and Bob’s private keys and corresponding public keys (in uncompressed format) are printed.
// The shared secret keys for Alice and Bob are printed, which should be identical.
// Potential Improvements:
// Error Handling:

// More robust error handling could be added, such as checking if the public keys are valid elliptic curve points and if the private keys are valid.
// Security:

// In practice, Diffie-Hellman key exchange with ECC requires careful handling to prevent attacks like side-channel or man-in-the-middle (MITM). Here, it’s a simplified version that assumes a secure channel for exchanging the public keys.
// Optimization:

// In more complex scenarios, it's important to ensure that operations are optimized for performance, especially when working with large numbers and cryptographic functions.
// Key Size and Curve:

// The code uses a fixed elliptic curve (secp256k1-style curve), but real-world implementations may require more flexible key sizes and curves depending on the security requirements.
// Let me know if you'd like to dive deeper into any specific aspect!

import 'dart:typed_data';

BigInt power(BigInt a, BigInt b, BigInt P) {
  return a.modPow(b, P);
}

// Generate public key from private key
List<BigInt> generatePublicKey(
    BigInt privateKey, BigInt Gx, BigInt Gy, BigInt P) {
  return [power(Gx, privateKey, P), power(Gy, privateKey, P)];
}

// Compute shared secret key
BigInt computeSharedKey(BigInt receivedPublicKey, BigInt privateKey, BigInt P) {
  return power(receivedPublicKey, privateKey, P);
}

// Compute shared secret key and return it as Uint8List
Uint8List computeSharedKeyToUint8List(
    BigInt receivedPublicKey, BigInt privateKey, BigInt P) {
  BigInt sharedKey = power(receivedPublicKey, privateKey, P);

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

void main() {
  BigInt P = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);
  BigInt Gx = BigInt.parse(
      '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
      radix: 16);
  BigInt Gy = BigInt.parse(
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162cb1baaa2c7e5d74b902d096fd5b91d1',
      radix: 16);
  print(
      "The generator point G (x, y) : (${Gx.toRadixString(16)}, ${Gy.toRadixString(16)})");

  // Alice's private key
  BigInt a =
      BigInt.parse('c8f3a74eb3d2c4b7b6e1ef6e34cf74a1c1eaf3eb', radix: 16);
  print("The private key a for Alice : $a");
  List<BigInt> alicePublicKey = generatePublicKey(a, Gx, Gy, P);
  print(
      "Alice's public key (uncompressed): 04${alicePublicKey[0].toRadixString(16).padLeft(64, '0')}${alicePublicKey[1].toRadixString(16).padLeft(64, '0')}");

  // Bob's private key
  BigInt b =
      BigInt.parse('a4d1c5a1f3f7ecf9b5a3d2c9e74a1c2b3f6e1d8a', radix: 16);
  print("The private key b for Bob : $b");
  List<BigInt> bobPublicKey = generatePublicKey(b, Gx, Gy, P);
  print(
      "Bob's public key (uncompressed): 04${bobPublicKey[0].toRadixString(16).padLeft(64, '0')}${bobPublicKey[1].toRadixString(16).padLeft(64, '0')}");

  // Compute shared secret key
  BigInt aliceShared = computeSharedKey(bobPublicKey[0], a, P);
  BigInt bobShared = computeSharedKey(alicePublicKey[0], b, P);
  print("Secret key for Alice: ${aliceShared.toRadixString(16)}");
  print("Secret key for Bob:   ${bobShared.toRadixString(16)}");
}

Uint8List generateP256SharedSecret(Uint8List publicKey, Uint8List privatekey) {
  BigInt P = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);

  final alicePublickey = publicKeyFromUint8List(publicKey);

  final b = privateKeyFromUint8List(privatekey);

  BigInt sharedKey = computeSharedKey(alicePublickey[0], b, P);

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
