import 'dart:typed_data';

import 'extension.dart';
import 'handshake.dart';

/**
 * Section 7.4.1.2
 */
class ServerHello {
  ProtocolVersion client_version;
  TlsRandom random;
  int session_id_length;
  List<int> session_id;
  int cipher_suite;
  int compression_method;
  Map<ExtensionType, Extension> extensions;

  ServerHello(
      this.client_version,
      this.random,
      this.session_id_length,
      this.session_id,
      this.cipher_suite,
      this.compression_method,
      this.extensions);

  static ServerHello unmarshal(Uint8List data, int offset) {
    var reader = ByteData.sublistView(data);

    final client_version =
        ProtocolVersion(reader.getUint8(offset), reader.getUint8(offset + 1));
    offset += 2;
    print("Protocol version: $client_version");

    final random = TlsRandom.fromBytes(data, offset);
    offset += 32;

    final session_id_length = reader.getUint8(offset);
    offset += 1;
    print("Session id length: $session_id_length");

    final session_id = session_id_length > 0
        ? data.sublist(offset, offset + session_id_length)
        : Uint8List(0);
    offset += session_id.length;
    print("Session id: $session_id");

    // final cookieLength = data[offset];
    // offset += 1;

    // final cookie = data.sublist(offset, offset + cookieLength);
    // offset += cookie.length;

    final cipherSuiteID =
        ByteData.sublistView(data, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;

    final ompressionMethodID = data[offset];
    offset++;

    print("Compression methods: $ompressionMethodID");

    final extensions = decodeExtensionMap(data, offset, data.length);
    print("extensions: $extensions");

    return ServerHello(client_version, random, session_id_length, session_id,
        cipherSuiteID, ompressionMethodID, extensions);
  }

  static (List<int>, int, bool?) decodeCipherSuiteIDs(
      Uint8List buf, int offset, int arrayLen) {
    final length =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    final count = length / 2;
    offset += 2;

    print("Cipher suite length: $length");

    List<int> result = List.filled(count.toInt(), 0);
    for (int i = 0; i < count.toInt(); i++) {
      result[i] = ByteData.sublistView(buf, offset, offset + 2)
          .getUint16(0, Endian.big);
      offset += 2;
      print("cipher suite: ${result[i]}");
    }

    // print("Cipher suites: $result");
    return (result, offset, null);
  }

  static (List<int>, int, bool?) decodeCompressionMethodIDs(
      Uint8List buf, int offset, int arrayLen) {
    final count = buf[offset];
    offset += 1;
    List<int> result = List.filled(count.toInt(), 0);
    for (int i = 0; i < count; i++) {
      result[i] = ByteData.sublistView(buf, offset, offset + 2).getUint8(0);
      offset += 1;
    }

    return (result, offset, null);
  }
}

void main() {
  ServerHello.unmarshal(raw_server_hello, 0);
}

final raw_server_hello = Uint8List.fromList([
  0xfe,
  0xfd,
  0x21,
  0x63,
  0x32,
  0x21,
  0x81,
  0x0e,
  0x98,
  0x6c,
  0x85,
  0x3d,
  0xa4,
  0x39,
  0xaf,
  0x5f,
  0xd6,
  0x5c,
  0xcc,
  0x20,
  0x7f,
  0x7c,
  0x78,
  0xf1,
  0x5f,
  0x7e,
  0x1c,
  0xb7,
  0xa1,
  0x1e,
  0xcf,
  0x63,
  0x84,
  0x28,
  0x00,
  0xc0,
  0x2b,
  0x00,
  0x00,
  0x00,
]);
