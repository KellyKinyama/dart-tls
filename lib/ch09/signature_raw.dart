import 'dart:convert';
import 'dart:typed_data';
import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

Uint8List signMessage(Uint8List message, ECPrivateKey privateKey) {
  final signer = ECDSASigner(SHA256Digest())..init(true, PrivateKeyParameter(privateKey));

  final ecSignature = signer.generateSignature(message) as ECSignature;

  // Ensure r and s are 32 bytes each (P-256 curve)
  Uint8List rBytes = BigIntToBytes(ecSignature.r, 32);
  Uint8List sBytes = BigIntToBytes(ecSignature.s, 32);

  // Concatenate r || s
  return Uint8List.fromList([...rBytes, ...sBytes]);
}

// Helper to convert BigInt to fixed-size byte array
Uint8List BigIntToBytes(BigInt value, int length) {
  final bytes = value.toUnsigned(256).toRadixString(16).padLeft(length * 2, '0');
  return Uint8List.fromList(List.generate(length, (i) => int.parse(bytes.substring(i * 2, (i + 1) * 2), radix: 16)));
}

void main() {
  // Generate EC Key Pair (secp256r1 / prime256v1)
  var keyPair = CryptoUtils.generateEcKeyPair(curve: 'prime256v1');
  var privateKey = keyPair.privateKey as ECPrivateKey;

  // Message to sign
  final message = utf8.encode("Hello, DTLS!") as Uint8List;

  // Generate raw R|S signature
  Uint8List rawSignature = signMessage(message, privateKey);

  // Send this over DTLS
  print("Signature (hex): ${rawSignature.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}");
}
