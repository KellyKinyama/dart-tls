import 'dart:typed_data';

class DtlsHandshake {
  final int msgType; // Message type (e.g., ClientHello)
  final int length; // Length of the message body
  final int messageSeq; // Sequence number for the message
  final int fragmentOffset; // Offset in case of fragmentation
  final int fragmentLength; // Length of the current fragment
  final List<int> body; // The actual handshake message body

  DtlsHandshake({
    required this.msgType,
    required this.length,
    required this.messageSeq,
    required this.fragmentOffset,
    required this.fragmentLength,
    required this.body,
  });

  List<int> encode() {
    final byteData = ByteData(10 + body.length);
    byteData.setInt8(0, msgType);
    byteData.setInt24(1, length);
    byteData.setInt16(4, messageSeq);
    byteData.setInt24(6, fragmentOffset);
    byteData.setInt24(9, fragmentLength);
    byteData.buffer.asUint8List().setRange(12, 12 + body.length, body);

    return byteData.buffer.asUint8List();
  }

  @override
  String toString() {
    return 'DtlsHandshake(msgType: $msgType, length: $length, messageSeq: $messageSeq, fragmentOffset: $fragmentOffset, fragmentLength: $fragmentLength)';
  }
}

void main() {
  final handshake = DtlsHandshake(
    msgType: 1, // Example: ClientHello
    length: 128,
    messageSeq: 0,
    fragmentOffset: 0,
    fragmentLength: 128,
    body: [1, 2, 3, 4, 5], // Just an example, actual body data
  );

  final encoded = handshake.encode();
  print('Encoded Handshake: $encoded');
}
