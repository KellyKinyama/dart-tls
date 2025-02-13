import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_tls/ch09/ecdsa_example.dart';
import 'package:hex/hex.dart';
import 'package:x25519/x25519.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:elliptic/elliptic.dart';

import 'crypto.dart';
import 'ecdsa3.dart';
import 'hex2.dart';
import 'prf2.dart';

enum ECCurveType {
  Named_Curve(3);

  const ECCurveType(this.value);
  final int value;

  factory ECCurveType.fromInt(int value) {
    switch (value) {
      case 3:
        return Named_Curve;
      default:
        throw ArgumentError('Invalid ECCurveType value: $value');
    }
  }
}

// enum NamedCurve {
//   secp256r1,
//   secp384r1,
//   secp521r1,
//   x25519,
//   x448,
//   ffdhe2048,
//   ffdhe3072,
//   ffdhe4096,
//   ffdhe6144,
//   ffdhe8192;

//   const NamedCurve(this.value);
//   final int value;
// }

// enum NamedCurve {
//   prime256v1(0x0017),
//   prime384v1(0x0018),
//   prime521v1(0x0019),
//   x25519(0x001D),
//   x448(0x001E),
//   ffdhe2048(0x0100),
//   ffdhe3072(0x0101),
//   ffdhe4096(0x0102),
//   ffdhe6144(0x0103),
//   ffdhe8192(0x0104),
//   secp256k1(0x0012);
//   // secp256r1(0x0017),
//   // secp384r1(0x0018),
//   // secp521r1(0x0019),
//   // secp256k1(0x0012),
//   // secp256r1(0x0017),
//   // secp384r1(0x0018),
//   // secp521r1(0x0019),
//   // secp256k1(0x0012),
//   // secp256r1(0x0017),

//   const NamedCurve(this.value);
//   final int value;

//   factory NamedCurve.fromInt(int key) {
//     return values.firstWhere((element) => element.value == key);
//   }
// }

// enum ECCurve { X25519, X448, Curve25519, Curve448 }

void genKeyAndX25519() {
  var aliceKeyPair = generateKeyPair();
  var bobKeyPair = generateKeyPair();

  print("Alice public key: ${HEX.encode(aliceKeyPair.publicKey)}");
  print("Alice private key: ${HEX.encode(aliceKeyPair.privateKey)}");

  print("Bob public key: ${HEX.encode(bobKeyPair.publicKey)}");
  print("object Bob private key: ${HEX.encode(bobKeyPair.privateKey)}");

  var aliceSharedKey = X25519(aliceKeyPair.privateKey, bobKeyPair.publicKey);
  var bobSharedKey = X25519(bobKeyPair.privateKey, aliceKeyPair.publicKey);

  print("Secret is: ${ListEquality().equals(aliceSharedKey, bobSharedKey)}");
}

Uint8List generateKeyValueMessages(Uint8List clientRandom,
    Uint8List serverRandom, Uint8List publicKey, Uint8List privateKey) {
  ByteData serverECDHParams = ByteData(4);
  serverECDHParams.setUint8(0, ECCurveType.Named_Curve.value);
  serverECDHParams.setUint16(1, NamedCurve.prime256v1.value);
  serverECDHParams.setUint8(3, publicKey.length);

  final bb = BytesBuilder();
  bb.add(clientRandom);
  bb.add(serverRandom);
  bb.add(serverECDHParams.buffer.asUint8List());
  bb.add(publicKey);

  return bb.toBytes();
}

({Uint8List privateKey, Uint8List publicKey}) generateP256Keys() {
  var ec = getP256();
  var priv = ec.generatePrivateKey();
  var pub = priv.publicKey;

  print("public key: ${hexDecode(pub.toHex()).length}");
  print("priv: ${priv.bytes.length}");
  print("public key: ${hexDecode(pub.X.toRadixString(16)).length}");

  return (
    privateKey: Uint8List.fromList(priv.bytes),
    publicKey: Uint8List.fromList(hexDecode(pub.toCompressedHex()))
  );
}

// Future<({Uint8List privateKey, Uint8List publicKey})> generateP256Keys() async {
//   // In this example, we use ECDSA-P256-SHA256
//   final algorithm = cryptography.Ecdsa.p256(cryptography.Sha256());

//   // Generate a random key pair
//   final kepair = await algorithm.newKeyPair();
//   final publicKey = await kepair.extractPublicKey();

//   final priv = await kepair.extract();

//   // Sign a message
//   // final message = <int>[1, 2, 3];
//   // final signature = await algorithm.sign(
//   //   [1, 2, 3],
//   //   secretKey: secretKey,
//   // );

//   // // Anyone can verify the signature
//   // final isVerified = await algorithm.verify(
//   //   message: message,
//   //   signature: signature,
//   // );

//   return (
//     privateKey: Uint8List.fromList(priv.d),
//     publicKey: Uint8List.fromList(publicKey.toDer())
//   );
// }

({Uint8List privateKey, Uint8List publicKey}) generateX25519Keys() {
  var aliceKeyPair = generateKeyPair();

  print("Alice public key: ${aliceKeyPair.publicKey.length}");
  print("Alice private key: ${aliceKeyPair.privateKey.length}");

  return (
    privateKey: Uint8List.fromList(aliceKeyPair.privateKey),
    publicKey: Uint8List.fromList(aliceKeyPair.publicKey)
  );
}

Uint8List generateKeySignature(Uint8List clientRandom, Uint8List serverRandom,
    Uint8List publicKey, Uint8List privateKey) {
  final msg = generateKeyValueMessages(
      clientRandom, serverRandom, publicKey, privateKey);
  final handshakeMessage = sha256.convert(msg).bytes;
  final signatureBytes = ecdsaSign(privateKey, handshakeMessage);
  return Uint8List.fromList(signatureBytes);
}

Uint8List generatePreMasterSecret(Uint8List publicKey, Uint8List privateKey) {
  // TODO: For now, it generates only using X25519
  // https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L106
  return X25519(privateKey, publicKey);
}

Uint8List generateMasterSecret(
    Uint8List preMasterSecret, Uint8List clientRandom, Uint8List serverRandom) {
  // seed := append(append([]byte("master secret"), clientRandom...), serverRandom...)
  final seed = Uint8List.fromList(
      [...utf8.encode("master secret"), ...clientRandom, ...serverRandom]);

  final result = pHash(preMasterSecret, seed, 48);
  print(
      "Generated MasterSecret (not Extended) using Pre-Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>) SHA256");
  return result;
}

Uint8List generateExtendedMasterSecret(
    Uint8List preMasterSecret, Uint8List handshakeHash) {
  final seed = Uint8List.fromList(
      [...utf8.encode("extended master secret"), ...handshakeHash]);
  final result = pHash(preMasterSecret, seed, 48);
  print(
      "Generated extended MasterSecret (not Extended) using Pre-Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>) SHA256");
  return result;
}

Uint8List generateKeyingMaterial(Uint8List masterSecret, Uint8List clientRandom,
    Uint8List serverRandom, int length) {
  final seed = Uint8List.fromList([
    ...utf8.encode("EXTRACTOR-dtls_srtp"),
    ...clientRandom,
    ...serverRandom
  ]);
  final result = pHash(masterSecret, seed, length);
  print(
      "Generated Keying Material using Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)");
  return result;
}

class EncryptionKeys {
  final Uint8List masterSecret;
  final Uint8List clientWriteKey;
  final Uint8List serverWriteKey;
  final Uint8List clientWriteIV;
  final Uint8List serverWriteIV;

  EncryptionKeys({
    required this.masterSecret,
    required this.clientWriteKey,
    required this.serverWriteKey,
    required this.clientWriteIV,
    required this.serverWriteIV,
  });
}

EncryptionKeys generateEncryptionKeys(Uint8List masterSecret,
    Uint8List clientRandom, Uint8List serverRandom, int keyLen, int ivLen) {
  final seed = Uint8List.fromList(
      [...utf8.encode("key expansion"), ...serverRandom, ...clientRandom]);

  final keyMaterial = pHash(masterSecret, seed, (2 * keyLen) + (2 * ivLen));

  // Slicing the key material into separate keys and IVs
  final clientWriteKey = keyMaterial.sublist(0, keyLen);
  final serverWriteKey = keyMaterial.sublist(keyLen, 2 * keyLen);
  final clientWriteIV = keyMaterial.sublist(2 * keyLen, 2 * keyLen + ivLen);
  final serverWriteIV = keyMaterial.sublist(2 * keyLen + ivLen);

  // Return the EncryptionKeys object
  return EncryptionKeys(
    masterSecret: masterSecret,
    clientWriteKey: clientWriteKey,
    serverWriteKey: serverWriteKey,
    clientWriteIV: clientWriteIV,
    serverWriteIV: serverWriteIV,
  );
}

void main() {
  // genKeyAndX25519();
  final keys = generateX25519Keys();

  var hashHex =
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  var hash = hexDecode(hashHex);
  final signatureBytes = ecdsaSign(keys.privateKey, hash);

  var result = ecdsaVerify(keys.publicKey, hash, signatureBytes);

  // var result = verify(pub, hash, Signature.fromCompact(signatureBytes));
  print("Is verified: $result");
}
