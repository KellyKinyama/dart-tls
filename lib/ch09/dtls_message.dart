// class BaseDtlsHandshakeMessage {}

import 'dart:typed_data';
import 'package:dart_tls/ch09/handshake/change_cipher_spec.dart';
import 'package:dart_tls/ch09/handshake/handshake_context.dart';

import 'handshake/alert.dart';
import 'handshake/handshake.dart';
import 'handshake/handshake_header.dart';
import 'record_layer_header.dart';

class DtlsErrors {
  static const errIncompleteDtlsMessage =
      'data contains incomplete DTLS message';
  static const errUnknownDtlsContentType =
      'data contains unknown DTLS content type';
  static const errUnknownDtlsHandshakeType =
      'data contains unknown DTLS handshake type';
}

class DecodeDtlsMessageResult {
  final RecordLayerHeader? recordHeader;
  final HandshakeHeader? handshakeHeader;
  final dynamic message;
  // final int offset;

  DecodeDtlsMessageResult(
      this.recordHeader, this.handshakeHeader, this.message);

  static DecodeDtlsMessageResult decode(
      HandshakeContext context, Uint8List buf, int offset, int arrayLen) {
    if (arrayLen < 1) {
      throw ArgumentError(DtlsErrors.errIncompleteDtlsMessage);
    }

    // print("Header content type: ${ContentType.fromInt(buf[0])}");

    final (header, decodedOffset, err) =
        RecordLayerHeader.unmarshal(buf, offset: offset, arrayLen: arrayLen);

    // print("Record header: $header");

    //print("offset: $offset, decodedOffset: $decodedOffset");
    offset = decodedOffset;

    if (header.epoch < context.clientEpoch) {
      // Ignore incoming message
      print("Header epock: ${header.epoch}");
      offset += header.contentLen;
      return DecodeDtlsMessageResult(null, null, null);
    }

    context.clientEpoch = header.epoch;

    context.protocolVersion = header.protocolVersion;

    Uint8List? decryptedBytes;
    Uint8List? encryptedBytes;

    if (header.epoch > 0) {
      print("Data arrived encrypted!!!");
      throw UnimplementedError("Encryption is not yet implemented");
    }

    context.clientEpoch = header.epoch;

    // if (header.contentType != ContentType.content_handshake) {
    print("Content type: ${header.contentType}");
    // }
    switch (header.contentType) {
      case ContentType.content_handshake:
        if (decryptedBytes == null) {
          final offsetBackup = offset;
          final (handshakeHeader, decodedOffset, err) =
              HandshakeHeader.unmarshal(buf, offset, arrayLen);

          // print("handshake header: ${handshakeHeader.handshakeType}");

          offset = decodedOffset;

          if (handshakeHeader.length.value !=
              handshakeHeader.fragmentLength.value) {
            // Ignore fragmented packets
            print('Ignore fragmented packets: ${header.contentType}');
            return DecodeDtlsMessageResult(null, null, null);
          }

          final result =
              decodeHandshake(header, handshakeHeader, buf, offset, arrayLen);

          context.HandshakeMessagesReceived[handshakeHeader.handshakeType] =
              Uint8List.fromList(buf.sublist(offsetBackup, offset));

          return DecodeDtlsMessageResult(header, handshakeHeader, result);
        } else {
          final (handshakeHeader, decodedOffset, err) =
              HandshakeHeader.decode(decryptedBytes, 0, decryptedBytes.length);
          final result = decodeHandshake(header, handshakeHeader,
              decryptedBytes, 0, decryptedBytes.length);

          final copyArray = Uint8List.fromList(decryptedBytes);
          context.HandshakeMessagesReceived[handshakeHeader.handshakeType] =
              copyArray;

          return DecodeDtlsMessageResult(header, handshakeHeader, result);
        }

      case ContentType.content_change_cipher_spec:
        {
          print(" Content type: ${header.contentType}");

          // throw UnimplementedError(
          //     "Content type: ${header.contentType} is not implemented");

          var (changeCipherSpec, decodedOffset, err) =
              ChangeCipherSpec.unmarshal(buf, offset, arrayLen);

          print("Change cipher spec: $changeCipherSpec");

          return DecodeDtlsMessageResult(header, null, changeCipherSpec);
        }

      case ContentType.content_alert:
        final alert = Alert.unmarshal(buf, offset, arrayLen);

        return DecodeDtlsMessageResult(header, null, alert);

      // throw UnimplementedError("Unhandled content type: ${header.contentType}");
      default:
        {
          throw UnimplementedError(
              "Unhandled content type: ${header.contentType}");
        }
    }

    print("Message: $header");

    return DecodeDtlsMessageResult(null, null, null);
  }

  @override
  String toString() {
    // TODO: implement toString
    return "DtlsMessage(recordHeader: $recordHeader, handshakeHeader: $handshakeHeader, message: $message)";
  }
}

void main() {
  HandshakeContext context = HandshakeContext();
  DecodeDtlsMessageResult.decode(context, rawDtlsMsg, 0, rawDtlsMsg.length);
}

final rawDtlsMsg = Uint8List.fromList([
  22,
  254,
  253,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  39,
  0,
  127,
  1,
  0,
  0,
  115,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  115,
  254,
  253,
  103,
  146,
  42,
  71,
  152,
  94,
  17,
  98,
  238,
  96,
  121,
  212,
  84,
  208,
  209,
  7,
  127,
  234,
  186,
  105,
  152,
  213,
  72,
  209,
  201,
  212,
  153,
  102,
  93,
  138,
  166,
  111,
  0,
  0,
  0,
  8,
  192,
  43,
  192,
  10,
  192,
  47,
  192,
  20,
  1,
  0,
  0,
  65,
  0,
  13,
  0,
  16,
  0,
  14,
  4,
  3,
  5,
  3,
  6,
  3,
  4,
  1,
  5,
  1,
  6,
  1,
  8,
  7,
  255,
  1,
  0,
  1,
  0,
  0,
  10,
  0,
  8,
  0,
  6,
  0,
  23,
  0,
  29,
  0,
  24,
  0,
  11,
  0,
  2,
  1,
  0,
  0,
  23,
  0,
  0,
  0,
  0,
  0,
  14,
  0,
  12,
  0,
  0,
  9,
  108,
  111,
  99,
  97,
  108,
  104,
  111,
  115,
  116
]);
