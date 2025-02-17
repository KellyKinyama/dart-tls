import 'dart:convert';
import 'package:crypto/crypto.dart'; // Import SHA256 from the crypto package

// Hash function for message (SHA-256)
BigInt _hashMessage(String message) {
  // Create a SHA-256 hash of the message
  final bytes = utf8.encode(message);
  final hash = sha256.convert(bytes);
  return BigInt.parse(hash.toString(), radix: 16);
}
