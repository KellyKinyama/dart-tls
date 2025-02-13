import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

Uint8List ecSignature() {
  // Generate EC key pair using secp256r1 (prime256v1)
  var keyPair = CryptoUtils.generateEcKeyPair(curve: 'prime256v1');
  var privateKey = keyPair.privateKey as ECPrivateKey;

  // Message to sign
  final message = utf8.encode("Hello, world!") as Uint8List;

  // Cryptographically secure PRNG (reuse for multiple signatures)
  final rand = Random.secure();
  final fortunaPrng = FortunaRandom()
    ..seed(KeyParameter(Uint8List.fromList(
      List<int>.generate(32, (_) => rand.nextInt(256)),
    )));

  // ECDSA signer with SHA-256
  final signer = ECDSASigner(SHA256Digest())
    ..init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter(privateKey),
        fortunaPrng,
      ),
    );

  // Generate ECDSA signature
  final ecSignature = signer.generateSignature(message) as ECSignature;

  // Encode as ASN.1 (DER format)
  final encoded = ASN1Sequence(elements: [
    ASN1Integer(ecSignature.r),
    ASN1Integer(ecSignature.s),
  ]).encode();

  // Base64 URL encoding for transmission
  final signature = base64UrlEncode(encoded);

  print("Signature: $signature");

  return encoded;
}

Uint8List signWithPrivateKey(Uint8List privateKeyBytes, Uint8List message) {
  // Convert Uint8List to BigInt for ECPrivateKey
  final privateKeyInt = BigInt.parse(
    privateKeyBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
    radix: 16,
  );

  // Initialize EC Private Key (secp256r1)
  final domainParams = ECDomainParameters('prime256v1');
  final privateKey = ECPrivateKey(privateKeyInt, domainParams);

  // Message to sign

  // ECDSA signer with SHA-256
  final signer = ECDSASigner(SHA256Digest())
    ..init(true, PrivateKeyParameter(privateKey));

  // Generate signature
  final ecSignature = signer.generateSignature(message) as ECSignature;

  // Encode as ASN.1 (DER format)
  final encoded = ASN1Sequence(elements: [
    ASN1Integer(ecSignature.r),
    ASN1Integer(ecSignature.s),
  ]).encode();

  print("Signature (Base64): ${base64UrlEncode(encoded)}");

  return encoded;
}

/// Convert a Uint8List public key to an ECPublicKey
ECPublicKey getPublicKeyFromBytes(Uint8List publicKeyBytes) {
  final domainParams = ECDomainParameters('prime256v1');

  // Extract x and y coordinates (assuming uncompressed format 0x04 || X || Y)
  if (publicKeyBytes.length != 65 || publicKeyBytes[0] != 0x04) {
    throw ArgumentError('Invalid uncompressed public key format');
  }

  final x = BigInt.parse(
    publicKeyBytes
        .sublist(1, 33)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join(),
    radix: 16,
  );

  final y = BigInt.parse(
    publicKeyBytes
        .sublist(33, 65)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join(),
    radix: 16,
  );

  return ECPublicKey(domainParams.curve.createPoint(x, y), domainParams);
}

/// Verify an ECDSA signature
bool verifySignature(
    Uint8List message, Uint8List signature, Uint8List publicKeyBytes) {
  final publicKey = getPublicKeyFromBytes(publicKeyBytes);

  // Decode ASN.1 DER signature
  final asn1Parser = ASN1Parser(signature);
  final seq = asn1Parser.nextObject() as ASN1Sequence;
  final r = (seq.elements![0] as ASN1Integer).integer!;
  final s = (seq.elements![1] as ASN1Integer).integer!;

  // Initialize verifier
  final verifier = ECDSASigner(SHA256Digest())
    ..init(false, PublicKeyParameter(publicKey));

  // Verify signature
  return verifier.verifySignature(message, ECSignature(r, s));
}

void main() {
  // Example public key in uncompressed format (65 bytes: 0x04 || X || Y)
  Uint8List publicKeyBytes = Uint8List.fromList([
    0x04, // Uncompressed format
    ...List.generate(32, (i) => i + 1), // X coordinate (mock data)
    ...List.generate(32, (i) => i + 33), // Y coordinate (mock data)
  ]);

  // Example signed message
  Uint8List message = utf8.encode("Hello, world!") as Uint8List;

  // Example signature (generated previously)
  Uint8List signature = Uint8List.fromList([
    // Example ASN.1 DER-encoded signature (mock data)
    0x30, 0x44, 0x02, 0x20,
    ...List.generate(32, (i) => i + 1), // R value
    0x02, 0x20,
    ...List.generate(32, (i) => i + 33), // S value
  ]);

  // Verify the signature
  bool isValid = verifySignature(message, signature, publicKeyBytes);
  print("Signature valid: $isValid");
}
