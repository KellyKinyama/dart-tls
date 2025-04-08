// import 'dart:typed_data';
// import 'dart:math';
// import 'package:cryptography/cryptography.dart';
// import 'package:dart_tls/ch09/record_layer_header.dart';

// import 'handshake/handshake.dart';

// const int gcmTagLength = 16;
// const int gcmNonceLength = 12;
// const int headerSize = 13;

// class GCM {
//   final AesGcm _localGCM;
//   final AesGcm _remoteGCM;
//   final SecretKey localKey;
//   final SecretKey remoteKey;
//   final Uint8List localWriteIV;
//   final Uint8List remoteWriteIV;

//   GCM(this._localGCM, this.localKey, this.localWriteIV, this._remoteGCM,
//       this.remoteKey, this.remoteWriteIV);

//   static Future<GCM> create(Uint8List localKey, Uint8List localWriteIV,
//       Uint8List remoteKey, Uint8List remoteWriteIV) async {
//     final localGCM = AesGcm.with128bits();
//     final remoteGCM = AesGcm.with128bits();

//     return GCM(localGCM, SecretKey(localKey), localWriteIV, remoteGCM,
//         SecretKey(remoteKey), remoteWriteIV);
//   }

//   Future<Uint8List> encrypt(RecordLayerHeader header, Uint8List raw) async {
//     final nonce = Uint8List(gcmNonceLength);
//     nonce.setRange(0, 4, localWriteIV.sublist(0, 4));
//     nonce.setRange(4, 12, _randomBytes(8));

//     final additionalData = _generateAEADAdditionalData(header, raw.length);
//     final secretBox = await _localGCM.encrypt(raw,
//         secretKey: localKey, nonce: nonce, aad: additionalData);

//     return Uint8List.fromList(
//         nonce.sublist(4) + secretBox.cipherText + secretBox.mac.bytes);
//   }

//   Future<Uint8List> decrypt(RecordLayerHeader header, Uint8List inData) async {
//     if (header.contentType == ContentType.content_change_cipher_spec) {
//       return inData;
//     }

//     final nonce = Uint8List(gcmNonceLength)
//       ..setRange(0, 4, remoteWriteIV.sublist(0, 4))
//       ..setRange(4, 12, inData.sublist(0, 8));

//     final ciphertext = inData.sublist(8);
//     final additionalData =
//         _generateAEADAdditionalData(header, ciphertext.length - gcmTagLength);

//     try {
//       final secretBox = SecretBox(
//           ciphertext.sublist(0, ciphertext.length - gcmTagLength),
//           nonce: nonce,
//           mac: Mac(ciphertext.sublist(ciphertext.length - gcmTagLength)));

//       final decrypted = await _remoteGCM.decrypt(secretBox,
//           secretKey: remoteKey, aad: additionalData);
//       return Uint8List.fromList(decrypted);
//     } catch (e) {
//       throw Exception('DTLS decryption failed: $e');
//     }
//   }

//   Uint8List _randomBytes(int length) {
//     final rand = Random.secure();
//     return Uint8List.fromList(List.generate(length, (_) => rand.nextInt(256)));
//   }

//   Uint8List _generateAEADAdditionalData(
//       RecordLayerHeader header, int payloadLen) {
//     final additionalData = Uint8List(13);
//     final byteData = ByteData.sublistView(additionalData);

//     byteData.setUint16(0, header.epoch, Endian.big);
//     additionalData.setRange(2, 8, header.marshalSequence());
//     additionalData[8] = header.contentType.value;
//     byteData.setUint8(9, header.protocolVersion.major);
//     byteData.setUint8(9, header.protocolVersion.major);
//     byteData.setUint16(11, payloadLen, Endian.big);

//     return additionalData;
//   }
// }
