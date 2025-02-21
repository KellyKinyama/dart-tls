import 'dart:typed_data';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:dart_tls/ch09/record_layer_header.dart';

import 'handshake/handshake.dart';

const int gcmTagLength = 16;
const int gcmNonceImplicitLength = 4;
const int gcmNonceExplicitLength = 8;
const int gcmNonceLength = gcmNonceImplicitLength + gcmNonceExplicitLength;
const int headerSize = 13;

class GCM {
  final AesGcm _localGCM;
  final AesGcm _remoteGCM;
  final SecretKey localKey;
  final SecretKey remoteKey;
  final Uint8List localWriteIV;
  final Uint8List remoteWriteIV;

  GCM(this._localGCM, this.localKey, this.localWriteIV, this._remoteGCM,
      this.remoteKey, this.remoteWriteIV);

  static Future<GCM> create(Uint8List localKey, Uint8List localWriteIV,
      Uint8List remoteKey, Uint8List remoteWriteIV) async {
    final localGCM = AesGcm.with128bits();
    final remoteGCM = AesGcm.with128bits();

    return GCM(localGCM, SecretKey(localKey), localWriteIV, remoteGCM,
        SecretKey(remoteKey), remoteWriteIV);
  }

  Future<Uint8List> encrypt(RecordLayerHeader header, Uint8List raw) async {
    final explicitNonce = _randomBytes(gcmNonceExplicitLength);
    final nonce = Uint8List(gcmNonceLength)
      ..setRange(0, gcmNonceImplicitLength, localWriteIV)
      ..setRange(gcmNonceImplicitLength, gcmNonceLength, explicitNonce);

    final additionalData = _generateAEADAdditionalData(header, raw.length);
    final secretBox = await _localGCM.encrypt(raw,
        secretKey: localKey, nonce: nonce, aad: additionalData);

    // Ensure the MAC is appended at the correct position
    return Uint8List.fromList(
        explicitNonce + secretBox.cipherText + secretBox.mac.bytes);
  }

  Future<Uint8List> decrypt(RecordLayerHeader header, Uint8List inData) async {
    if (header.contentType == ContentType.content_change_cipher_spec) {
      return inData;
    }

    if (inData.length < gcmNonceExplicitLength + gcmTagLength) {
      throw Exception('Invalid ciphertext length');
    }

    // Extract explicit nonce (first 8 bytes)
    final explicitNonce = inData.sublist(0, gcmNonceExplicitLength);
    final nonce = Uint8List(gcmNonceLength)
      ..setRange(0, gcmNonceImplicitLength, remoteWriteIV)
      ..setRange(gcmNonceImplicitLength, gcmNonceLength, explicitNonce);

    // Separate ciphertext from MAC
    final ciphertext =
        inData.sublist(gcmNonceExplicitLength, inData.length - gcmTagLength);
    final mac = inData.sublist(inData.length - gcmTagLength);

    final additionalData =
        _generateAEADAdditionalData(header, ciphertext.length);

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: Mac(mac));

    try {
      // Decrypt the data
      final decrypted = await _remoteGCM.decrypt(secretBox,
          secretKey: remoteKey, aad: additionalData);
      return Uint8List.fromList(decrypted);
    } catch (e) {
      throw Exception('Decryption failed: $e');
    }
  }

  Uint8List _randomBytes(int length) {
    final rand = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rand.nextInt(256)));
  }

  Uint8List _generateAEADAdditionalData(
      RecordLayerHeader header, int payloadLen) {
    final additionalData = Uint8List(headerSize);
    final byteData = ByteData.sublistView(additionalData);

    byteData.setUint16(0, header.epoch, Endian.big);
    additionalData.setRange(2, 8, header.marshalSequence());
    additionalData[8] = header.contentType.value;
    byteData.setUint8(9, header.protocolVersion.major);
    byteData.setUint8(10, header.protocolVersion.minor);
    byteData.setUint16(11, payloadLen, Endian.big);

    return additionalData;
  }
}
