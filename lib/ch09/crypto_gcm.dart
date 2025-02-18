import 'dart:async';
import 'dart:typed_data';
import 'dart:math';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'handshake/handshake.dart';
import 'record_layer_header.dart';

const int gcmTagLength = 16;
const int gcmNonceLength = 12;
const int headerSize = 13;

class GCM {
  final cryptography.AesGcm localGCM;
  final cryptography.AesGcm remoteGCM;
  final Uint8List localWriteIV;
  final Uint8List remoteWriteIV;

  Uint8List localKey;
  Uint8List remoteKey;

  GCM._(this.localGCM, this.remoteGCM, this.localWriteIV, this.remoteWriteIV,
      this.localKey, this.remoteKey);

  /// Creates a DTLS GCM Cipher (AES-128-GCM)
  static Future<GCM> newGCM(Uint8List localKey, Uint8List localWriteIV,
      Uint8List remoteKey, Uint8List remoteWriteIV) async {
    final localGCM = cryptography.AesGcm.with128bits();
    final remoteGCM = cryptography.AesGcm.with128bits();
    return GCM._(
        localGCM, remoteGCM, localWriteIV, remoteWriteIV, localKey, remoteKey);
  }

  /// Encrypts a DTLS RecordLayer message
  /// Encrypts a DTLS RecordLayer message
  Future<Uint8List> encrypt(RecordLayerHeader header, Uint8List raw) async {
    final nonce = Uint8List(gcmNonceLength);
    nonce.setRange(0, 4, localWriteIV.sublist(0, 4));

    final random = Random.secure();
    for (int i = 4; i < gcmNonceLength; i++) {
      nonce[i] = random.nextInt(256);
    }

    final additionalData = generateAEADAdditionalData(header, raw.length);

    // Encrypt using the localSecretKey
    final secretBox = await localGCM.encrypt(
      raw,
      secretKey: cryptography.SecretKey(localKey),
      nonce: nonce,
      aad: additionalData,
    );

    final encryptedPayload = Uint8List.fromList(secretBox.concatenation());
    return Uint8List.fromList([...nonce.sublist(4), ...encryptedPayload]);
  }

  /// Decrypts a DTLS RecordLayer message
  /// Decrypts a DTLS RecordLayer message
//   Future<Uint8List> decrypt(RecordLayerHeader header, Uint8List inData) async {
//     final completer = Completer<bool>();
//     if (header.contentType == ContentType.content_change_cipher_spec) {
//       return inData; // Nothing to decrypt for ChangeCipherSpec
//     }

//     final encryptedPayload = inData.sublist(8);
//     final additionalData = generateAEADAdditionalData(
//         header, encryptedPayload.length - gcmTagLength);

//     //       final bb=BytesBuilder();
//     // final nonce =List.filled(gcmNonceLength, 0);
//     // bb.add(nonce);
//     // bb.add(remoteWriteIV.sublist(0,4));
//     // bb.add(inData.sublist(0,8));
//     // // nonce = append(append(nonce, g.remoteWriteIV[:4]...), in[0:8]...)
//     // final out := in[8:]

//     // additionalData := generateAEADAdditionalData(h, len(out)-gcmTagLength)
//     // var err error
//     // out, err = g.remoteGCM.Open(out[:0], nonce, out, additionalData)
//     // if err != nil {
//     // 	return nil, fmt.Errorf("error on decrypting packet: %v", err)
//     // }
//     // return out, nil

//     // try {
//     // final nonce = Uint8List(gcmNonceLength);
//     // nonce.setRange(0, 4, localWriteIV.sublist(0, 4));

//     // final random = Random.secure();
//     // for (int i = 4; i < gcmNonceLength; i++) {
//     //   nonce[i] = random.nextInt(256);
//     // }

// // Make sure it's used when encrypting:
//     // final secretBox = await localGCM.encrypt(
//     //   encryptedPayload,
//     //   secretKey: cryptography.SecretKey(localKey),
//     //   nonce: nonce, // Correctly use the nonce here
//     //   aad: additionalData,
//     // );

//     final secretBox = cryptography.SecretBox.fromConcatenation(encryptedPayload,
//         nonceLength: gcmNonceLength, macLength: gcmTagLength);

//     // Decrypt using the remoteSecretKey
//     final decrypted = await remoteGCM.decrypt(
//       secretBox,
//       secretKey:
//           cryptography.SecretKey(remoteKey), // Pass the required secretKey

//       aad: additionalData,
//     );

//     completer.complete(true);
//     return Uint8List.fromList(decrypted);
//     // } catch (e) {
//     //   throw Exception("Error decrypting packet: $e");
//     // }
//   }

  Future<Uint8List> decrypt(RecordLayerHeader header, Uint8List inData) async {
    if (header.contentType == ContentType.content_change_cipher_spec) {
      return inData; // Nothing to decrypt for ChangeCipherSpec
    }
    final completer = Completer<bool>();
    // Extract the nonce and encrypted payload
    // final nonce = Uint8List(gcmNonceLength);
    // nonce.setRange(0, 4, remoteWriteIV.sublist(0, 4));
    // nonce.setRange(4, gcmNonceLength, inData.sublist(0, 4));

    final bb = BytesBuilder();
    bb.add(remoteWriteIV.sublist(0, 4));
    bb.add(inData.sublist(0, 4));
    final nonce = bb.toBytes();

    final encryptedPayload = inData.sublist(8);

    // Prepare additional data for AEAD
    final additionalData = generateAEADAdditionalData(
        header, encryptedPayload.length - gcmTagLength);

    // Decrypt the data using the remote GCM key
    final secretBox = cryptography.SecretBox.fromConcatenation(encryptedPayload,
        nonceLength: nonce.length,
        macLength: encryptedPayload.length - gcmTagLength);
    final decrypted = await remoteGCM.decrypt(
      secretBox,
      secretKey: cryptography.SecretKey(remoteKey),
      aad: additionalData,
    );

    completer.complete(true);
    return Uint8List.fromList(decrypted);
  }
}

Uint8List generateAEADAdditionalData(RecordLayerHeader h, int payloadLen) {
  final additionalData = Uint8List(13);
  final byteData = ByteData.sublistView(additionalData);

  // Write Epoch (2 bytes)
  byteData.setUint16(0, h.epoch, Endian.big);

  // Copy SequenceNumber (6 bytes)
  additionalData.setRange(2, 8, h.marshalSequence());

  // Write ContentType (1 byte)
  additionalData[8] = h.contentType.index;

  // Write Version (2 bytes)
  byteData.setUint8(9, h.protocolVersion.major);
  byteData.setUint8(10, h.protocolVersion.minor);

  // Write Payload Length (2 bytes)
  byteData.setUint16(11, payloadLen, Endian.big);

  return additionalData;
}


// const (
// 	gcmTagLength   = 16
// 	gcmNonceLength = 12
// 	headerSize     = 13
// )

// type GCM struct {
// 	localGCM, remoteGCM         cipher.AEAD
// 	localWriteIV, remoteWriteIV []byte
// }

// // NewGCM creates a DTLS GCM Cipher
// func NewGCM(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*GCM, error) {
// 	localBlock, err := aes.NewCipher(localKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	localGCM, err := cipher.NewGCM(localBlock)
// 	if err != nil {
// 		return nil, err
// 	}

// 	remoteBlock, err := aes.NewCipher(remoteKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	remoteGCM, err := cipher.NewGCM(remoteBlock)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &GCM{
// 		localGCM:      localGCM,
// 		localWriteIV:  localWriteIV,
// 		remoteGCM:     remoteGCM,
// 		remoteWriteIV: remoteWriteIV,
// 	}, nil
// }

// // Encrypts a DTLS RecordLayer message
// func (g *GCM) Encrypt(header *RecordHeader, raw []byte) ([]byte, error) {
// 	nonce := make([]byte, gcmNonceLength)
// 	copy(nonce, g.localWriteIV[:4])
// 	if _, err := rand.Read(nonce[4:]); err != nil {
// 		return nil, err
// 	}

// 	additionalData := generateAEADAdditionalData(header, len(raw))
// 	encryptedPayload := g.localGCM.Seal(nil, nonce, raw, additionalData)
// 	r := make([]byte, len(nonce[4:])+len(encryptedPayload))
// 	copy(r, nonce[4:])
// 	copy(r[len(nonce[4:]):], encryptedPayload)
// 	return r, nil
// }

// // Decrypts a DTLS RecordLayer message
// func (g *GCM) Decrypt(h *RecordHeader, in []byte) ([]byte, error) {
// 	switch {
// 	case h.ContentType == ContentTypeChangeCipherSpec:
// 		// Nothing to encrypt with ChangeCipherSpec
// 		return in, nil
// 	}

// 	nonce := make([]byte, 0, gcmNonceLength)
// 	nonce = append(append(nonce, g.remoteWriteIV[:4]...), in[0:8]...)
// 	out := in[8:]

// 	additionalData := generateAEADAdditionalData(h, len(out)-gcmTagLength)
// 	var err error
// 	out, err = g.remoteGCM.Open(out[:0], nonce, out, additionalData)
// 	if err != nil {
// 		return nil, fmt.Errorf("error on decrypting packet: %v", err)
// 	}
// 	return out, nil
// }