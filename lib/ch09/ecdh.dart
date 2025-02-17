import 'dart:typed_data';
import 'package:pinenacl/api.dart';  // For X25519 ECDH
import 'package:convert/convert.dart';  // For hex encoding

// Function to generate a shared secret
Uint8List generatePreMasterSecret(Uint8List publicKey, Uint8List privateKey) {
  // Create X25519 instance for the key exchange
  final x25519 = X25519();

  // Generate the shared secret using X25519 ECDH
  final sharedSecret = x25519.sharedSecret(privateKey, publicKey);

  return sharedSecret;
}