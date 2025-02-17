import 'dart:convert';
import 'dart:typed_data';

class DtlsRecord {
  final int type; // ContentType
  final List<int> version; // ProtocolVersion (e.g., [254, 253] for DTLS 1.2)
  final int epoch; // Epoch
  final int sequenceNumber; // Sequence number
  final List<int> fragment; // Fragment (actual data)

  DtlsRecord({
    required this.type,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
    required this.fragment,
  });

  // Encode to a byte array
  List<int> encode() {
    // Calculate total length: 6 fixed fields + fragment length
    final int totalLength = 6 + 2 + 2 + 8 + 2 + fragment.length;
    final byteData = ByteData(totalLength);

    // Set values in the ByteData buffer
    byteData.setInt8(0, type); // ContentType
    byteData.setInt8(1, version[0]); // ProtocolVersion[0]
    byteData.setInt8(2, version[1]); // ProtocolVersion[1]
    byteData.setInt16(3, epoch); // Epoch
    byteData.setInt64(5, sequenceNumber); // Sequence number (48 bits)
    byteData.setInt16(13, fragment.length); // Length of fragment
    byteData.buffer.asUint8List().setRange(15, 15 + fragment.length, fragment);

    return byteData.buffer.asUint8List();
  }

  @override
  String toString() {
    return 'DtlsRecord(type: $type, version: $version, epoch: $epoch, sequenceNumber: $sequenceNumber, fragment: ${utf8.decode(fragment)})';
  }
}

void main() {
  final record = DtlsRecord(
    type: 23, // Handshake message type
    version: [254, 253], // DTLS 1.2
    epoch: 1,
    sequenceNumber: 12345,
    fragment: utf8.encode("Hello, DTLS world!"),
  );

  final encodedRecord = record.encode();
  print('Encoded DTLS Record: ${encodedRecord}');
}
