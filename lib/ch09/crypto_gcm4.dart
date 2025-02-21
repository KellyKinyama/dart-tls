import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

void main() async {
  // Define the AES-GCM cipher (128-bit)
  final algorithm = AesGcm.with128bits();

  // Generate a 16-byte AES key
  final secretKey = SecretKey(List.generate(16, (i) => i));

  // Generate a 12-byte nonce (IV) for AES-GCM
  final nonce = Uint8List.fromList(List.generate(12, (i) => i + 1));

  // Plaintext message
  final plaintext = Uint8List.fromList("Hello, DTLS AEAD!".codeUnits);

  // Additional Authenticated Data (AAD)
  final aad = Uint8List.fromList("DTLS Header".codeUnits);

  // Encrypt using AES-GCM with AAD
  final secretBox = await algorithm.encrypt(
    plaintext,
    secretKey: secretKey,
    nonce: nonce, // Using Uint8List instead of Nonce
    aad: aad,
  );

  print("Ciphertext: ${secretBox.cipherText}");
  print("MAC (Tag): ${secretBox.mac.bytes}");

  final sealBox = SecretBox(secretBox.cipherText,
      nonce: nonce, mac: Mac(secretBox.mac.bytes));

  // Decrypt using AES-GCM with AAD
  final decrypted = await algorithm.decrypt(
    sealBox,
    secretKey: secretKey,
    aad: aad, // AAD must match exactly
  );

  print("Decrypted: ${String.fromCharCodes(decrypted)}");
}
