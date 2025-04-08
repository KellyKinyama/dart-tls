// import 'dart:typed_data';
// import 'package:cryptography/cryptography.dart';

// import 'handshake/handshake.dart';
// import 'record_layer_header.dart';

// const int gcmTagLength = 16;
// const int gcmNonceImplicitLength = 4;
// const int gcmNonceExplicitLength = 8;
// const int gcmNonceLength = gcmNonceImplicitLength + gcmNonceExplicitLength;
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

//   Future<Uint8List> decrypt(RecordLayerHeader header, Uint8List inData) async {
//     if (header.contentType == ContentType.content_change_cipher_spec) {
//       return inData; // Handle the case where no encryption occurs
//     }

//     if (inData.length < gcmNonceLength + gcmTagLength) {
//       throw Exception('Invalid ciphertext length');
//     }

//     // Step 1: Construct the nonce
//     final nonce = Uint8List(gcmNonceLength);
//     nonce.setRange(
//         0, 4, remoteWriteIV.sublist(0, 4)); // First 4 bytes of remoteWriteIV
//     nonce.setRange(
//         4,
//         gcmNonceLength,
//         inData.sublist(
//             0, 8)); // First 8 bytes of the ciphertext as the explicit part

//     // Step 2: Extract encrypted data and authentication tag
//     final encrypted = inData.sublist(8, inData.length - gcmTagLength);
//     final authTag = inData.sublist(inData.length - gcmTagLength);

//     // Step 3: Generate Additional Authentication Data (AAD)
//     final additionalData =
//         _generateAEADAdditionalData(header, encrypted.length);

//     // Step 4: Decrypt using the SecretBox
//     // final secretBox = SecretBox(encrypted, nonce: nonce, mac: Mac(authTag));

//     final secretBox = SecretBox.fromConcatenation(nonce + encrypted + authTag,
//         nonceLength: nonce.lengthInBytes, macLength: authTag.lengthInBytes);

//     // try {
//     // Decrypt the data using AesGcm.decrypt
//     final decrypted = await _remoteGCM.decrypt(secretBox,
//         secretKey: remoteKey, aad: additionalData);

//     print("decripted bytes: $decrypted");
//     return Uint8List.fromList(decrypted);
//     // } catch (e) {
//     //   throw Exception('Decryption failed: $e');
//     // }
//   }

// //   Future<Uint8List> decrypt(RecordLayerHeader header, Uint8List inData) async {
// //     if (header.contentType == ContentType.content_change_cipher_spec) {
// //       return inData; // Handle the case where no encryption occurs
// //     }

// //   // /nonce := make([]byte, 0, gcmNonceLength)
// // 	// nonce = append(append(nonce, g.remoteWriteIV[:4]...), in[0:8]...)
// // 	final out = inData.sublist(8);

// //   final nonce=BytesBuilder();
// //   nonce.add(remoteWriteIV.sublist(0,4));
// //    nonce.add(inData.sublist(0,8));

// // 	final additionalData = _generateAEADAdditionalData(header, out.length-gcmTagLength);

// //   SecretBox.fromConcatenation(data, nonceLength: nonceLength, macLength: macLength)

// //   final secretBox = SecretBox(encrypted, nonce: nonce, mac: Mac(authTag));
// // 	// var err error
// // 	// out, err = g.remoteGCM.Open(out[:0], nonce, out, additionalData)
// // 	// if err != nil {
// // 	// 	return nil, fmt.Errorf("error on decrypting packet: %v", err)
// // 	// }
// // 	// return out, nil
// //  }

//   // Helper method to generate AAD (Additional Authentication Data)
//   Uint8List _generateAEADAdditionalData(
//       RecordLayerHeader header, int payloadLen) {
//     final additionalData = Uint8List(headerSize);
//     final byteData = ByteData.sublistView(additionalData);

//     byteData.setUint16(0, header.epoch, Endian.big); // Set the epoch (2 bytes)
//     additionalData.setRange(
//         2, 8, header.marshalSequence()); // Set the sequence number (6 bytes)
//     additionalData[8] =
//         header.contentType.value; // Set the content type (1 byte)
//     byteData.setUint8(
//         9, header.protocolVersion.major); // Set major version (1 byte)
//     byteData.setUint8(
//         10, header.protocolVersion.minor); // Set minor version (1 byte)
//     byteData.setUint16(
//         11, payloadLen, Endian.big); // Set the length of the data

//     return additionalData;
//   }
// }
