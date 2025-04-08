import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

const int srtpAuthTagLength = 16;
const int srtpIVLength = 12;

class SRTP {
  final AesGcm _srtpGCM;
  final AesGcm _srtcpGCM;
  final SecretKey srtpKey;
  final SecretKey srtcpKey;
  final Uint8List srtpSalt;
  final Uint8List srtcpSalt;

  SRTP(this._srtpGCM, this.srtpKey, this.srtpSalt, this._srtcpGCM,
      this.srtcpKey, this.srtcpSalt);

  static Future<SRTP> create(Uint8List masterKey, Uint8List masterSalt) async {
    final srtpKey =
        await _deriveKey(masterKey, masterSalt, 0x00, masterKey.length);
    final srtcpKey =
        await _deriveKey(masterKey, masterSalt, 0x03, masterKey.length);
    final srtpSalt =
        await _deriveKey(masterKey, masterSalt, 0x02, masterSalt.length);
    final srtcpSalt =
        await _deriveKey(masterKey, masterSalt, 0x05, masterSalt.length);

    return SRTP(AesGcm.with128bits(), SecretKey(srtpKey), srtpSalt,
        AesGcm.with128bits(), SecretKey(srtcpKey), srtcpSalt);
  }

  Future<Uint8List> decrypt(
      Uint8List ciphertext, Uint8List header, int roc) async {
    if (ciphertext.length < srtpAuthTagLength) {
      throw Exception('Invalid SRTP packet length');
    }

    final nonce = _generateIV(header, roc, srtpSalt);
    final encryptedPayload = ciphertext.sublist(
        header.length, ciphertext.length - srtpAuthTagLength);
    final authTag = ciphertext.sublist(ciphertext.length - srtpAuthTagLength);

    final secretBox = SecretBox.fromConcatenation(
      nonce + encryptedPayload + authTag,
      nonceLength: nonce.lengthInBytes,
      macLength: authTag.lengthInBytes,
    );

    try {
      final decrypted =
          await _srtpGCM.decrypt(secretBox, secretKey: srtpKey, aad: header);
      return Uint8List.fromList(header + decrypted);
    } catch (e) {
      throw Exception('Decryption failed: $e');
    }
  }

  static Future<Uint8List> _deriveKey(
      Uint8List masterKey, Uint8List masterSalt, int label, int length) async {
    final prfInput = Uint8List(masterKey.length)..setAll(0, masterSalt);
    prfInput[7] ^= label;

    final aes = AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty);
    final derivedKey =
        await aes.encrypt(prfInput, secretKey: SecretKey(masterKey));

    final derivedKeyBytes = derivedKey.cipherText.sublist(0, length);
    return Uint8List.fromList(derivedKeyBytes);
  }

  Uint8List _generateIV(Uint8List header, int roc, Uint8List salt) {
    final iv = Uint8List(srtpIVLength);
    final byteData = ByteData.sublistView(iv);

    byteData.setUint32(2, _extractSSRC(header), Endian.big);
    byteData.setUint32(6, roc, Endian.big);
    byteData.setUint16(10, _extractSequenceNumber(header), Endian.big);

    for (int i = 0; i < iv.length; i++) {
      iv[i] ^= salt[i];
    }
    return iv;
  }

  int _extractSSRC(Uint8List header) {
    return ByteData.sublistView(header).getUint32(8, Endian.big);
  }

  int _extractSequenceNumber(Uint8List header) {
    return ByteData.sublistView(header).getUint16(2, Endian.big);
  }
}
