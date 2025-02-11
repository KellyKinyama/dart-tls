// class BaseDtlsHandshakeMessage {}

import 'dart:typed_data';
import 'package:dart_tls/ch09/handshake/handshake_context.dart';

import 'handshake/handshake_header.dart';
import 'record_layer_header.dart';

class DecodeDtlsMessageResult {
  final RecordLayerHeader? recordHeader;
  final HandshakeHeader? handshakeHeader;
  final dynamic message;
  final int offset;

  DecodeDtlsMessageResult(
      {this.recordHeader,
      this.handshakeHeader,
      this.message,
      required this.offset});

  static decode(HandshakeContext context, Uint8List data, int i, int length) {}
}
