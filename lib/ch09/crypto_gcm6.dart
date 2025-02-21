import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

void main() async {
  // Parse hex values
  final iv = hexToBytes("14cdba450001000000000001");
  final explicitNonce = hexToBytes("0001000000000001");
  final writeKey = hexToBytes("02e9390c5e32dc1efc4d164668e63044");
  final additionalBuffer = hexToBytes("000100000000000117fefd0011");
  final data = hexToBytes("68656c6c6f2066726f6d20636c69656e74");
  final encryptedHeadPart = hexToBytes("354af591d5d651044ff67e94cef40d5499");
  final authTag = hexToBytes("958b2f354d4366217aa3a1e99ca00791");

  // Combine nonce and IV
  final nonce = Uint8List(12);
  nonce.setRange(0, 4, iv.sublist(0, 4)); // IV prefix
  nonce.setRange(4, 12, explicitNonce); // Explicit nonce suffix

  print("[Dart] IV: ${bytesToHex(iv)}");
  print("[Dart] Explicit Nonce: ${bytesToHex(explicitNonce)}");
  print("[Dart] Nonce: ${bytesToHex(nonce)}");
  print("[Dart] Write Key: ${bytesToHex(writeKey)}");
  print("[Dart] Additional Buffer: ${bytesToHex(additionalBuffer)}");
  print("[Dart] Data: ${bytesToHex(data)}");

  // Encrypt using AES-GCM
  final algorithm = AesGcm.with128bits();
  final secretKey = SecretKey(writeKey);
  final secretBox = await algorithm.encrypt(
    data,
    secretKey: secretKey,
    nonce: nonce,
    aad: additionalBuffer,
  );

  print(
      "[Dart] Encrypted Head Part: ${bytesToHex(Uint8List.fromList(secretBox.cipherText))}");
  print(
      "[Dart] Auth Tag: ${bytesToHex(Uint8List.fromList(secretBox.mac.bytes))}");

  // Check if encryption matches expected values
  print(
      "[Check] Matches Head Part: ${bytesToHex(Uint8List.fromList(secretBox.cipherText)) == bytesToHex(encryptedHeadPart)}");
  print(
      "[Check] Matches Auth Tag: ${bytesToHex(Uint8List.fromList(secretBox.mac.bytes)) == bytesToHex(authTag)}");
}

// Helper functions for hex conversion
Uint8List hexToBytes(String hex) {
  return Uint8List.fromList(List.generate(hex.length ~/ 2,
      (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16)));
}

String bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
