import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:hex/hex.dart';

void main() {
  // Load the P-256 curve
  final curve = getSecp256r1();

  // final ke;

  // Generate a private key
  final privateKey =
      PrivateKey(curve, BigInt.parse("1234567890abcdef", radix: 16));
  final publicKey = privateKey.publicKey;

  print("Private Key: ${privateKey.toHex()}");
  print("Public Key: (${publicKey.X}, ${publicKey.Y})");

  // Message to sign
  final message = utf8.encode("Hello, ECDSA in Dart!");
  final hash = sha256.convert(message).bytes; // Compute SHA-256 hash

  // Sign the hash using ECDSA
  final sig =
      signature(PrivateKey(curve, privateKey.D), Uint8List.fromList(hash));

  print("Signature: r=${sig.R}, s=${sig.S}");

  // Verify the signature
  final isValid = verify(publicKey, Uint8List.fromList(hash), sig);

  print("Signature Valid: $isValid");
}

void main2() {
  // Load the P-256 curve
  final curve = getSecp256r1();

  // Example public key bytes (replace with actual bytes)
  final publicKeyBytes = HEX.decode(
      "04c7f3a0eecf4382b3a13d5e48862f917f2c8a4d2ac83b292a790ec3b1e87e530d88b4a0b916d4f6739b47c1f62c6b93f1c812db283ff705399c3c8754b06dc8ae");

  // Extract X and Y coordinates
  final x = BigInt.parse(HEX.encode(publicKeyBytes.sublist(1, 33)), radix: 16);
  final y = BigInt.parse(HEX.encode(publicKeyBytes.sublist(33, 65)), radix: 16);

  // Construct PublicKey from X and Y coordinates
  final publicKey = PublicKey(curve, x, y);

  print("✅ Public Key: (${publicKey.X}, ${publicKey.Y})");
}
