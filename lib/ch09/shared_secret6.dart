import 'dart:typed_data';

// Power function for modular exponentiation
BigInt power(BigInt a, BigInt b, BigInt P) {
  return a.modPow(b, P);
}

// Generate public key from private key
List<BigInt> generatePublicKey(
    BigInt privateKey, BigInt Gx, BigInt Gy, BigInt P) {
  return [power(Gx, privateKey, P), power(Gy, privateKey, P)];
}

// Compute shared secret key from uncompressed public key
BigInt computeSharedKey(BigInt receivedPublicKeyX, BigInt receivedPublicKeyY,
    BigInt privateKey, BigInt P) {
  // Elliptic curve point multiplication for shared key
  // This is a simplified example and assumes a proper elliptic curve implementation
  // In practice, you need elliptic curve math, but we're assuming some generic method here
  return power(receivedPublicKeyX, privateKey,
      P); // Simplified version for demonstration
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

  // Convert Bob's public key to BigInt (x and y)
  List<BigInt> bobPublicKeyCoords = publicKeyFromUint8List(Uint8List.fromList([
    0x04, // Uncompressed public key format
    ...bobPublicKey[0].toRadixString(16).padLeft(64, '0').runes,
    ...bobPublicKey[1].toRadixString(16).padLeft(64, '0').runes,
  ]));

  // Compute shared secret key for Alice using Bob's public key and Alice's private key
  BigInt aliceShared =
      computeSharedKey(bobPublicKeyCoords[0], bobPublicKeyCoords[1], a, P);
  // Compute shared secret key for Bob using Alice's public key and Bob's private key
  BigInt bobShared =
      computeSharedKey(alicePublicKey[0], alicePublicKey[1], b, P);

  // Output the shared secret keys
  print("Secret key for Alice: ${aliceShared.toRadixString(16)}");
  print("Secret key for Bob:   ${bobShared.toRadixString(16)}");
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

Uint8List generateP256SharedSecret(Uint8List publicKey, Uint8List privatekey) {
  BigInt P = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);

  final alicePublicKey = publicKeyFromUint8List(publicKey);

  final b = privateKeyFromUint8List(privatekey);

  BigInt sharedKey =
      computeSharedKey(alicePublicKey[0], alicePublicKey[1], b, P);

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
