import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

Uint8List sha256Hash(Uint8List input) {
  // Convert input string to bytes
  // final bytes = utf8.encode(input);

  // Hash the input using SHA-256
  final digest = sha256.convert(input);

  // Return the hexadecimal representation of the hash
  return Uint8List.fromList(digest.bytes);
}

// void main() {
//   String message = "Hello, World!";
//   String hashedMessage = sha256Hash(message);
//   print("SHA-256 Hash: $hashedMessage");
// }
