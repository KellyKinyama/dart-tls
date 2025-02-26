import 'dart:typed_data';
import 'header.dart';

class Packet {
  final Header header;
  final int headerSize;
  final Uint8List payload;
  final Uint8List rawData;

  Packet({
    required this.header,
    required this.headerSize,
    required this.payload,
    required this.rawData,
  });

  static Packet? decodePacket(Uint8List buf, int offset, int arrayLen) {
    try {
      Uint8List rawData =
          Uint8List.fromList(buf.sublist(offset, offset + arrayLen));
      int offsetBackup = offset;
      var (header,decodedOffset) = Header.decodeHeader(buf, offset, arrayLen);
      if (header == null) return null;
      offset += header.headerSize;

      int lastPosition = arrayLen;
      if (header.padding) {
        int paddingSize = buf[arrayLen - 1];
        lastPosition = arrayLen - paddingSize;
      }
      Uint8List payload = buf.sublist(offset, lastPosition);

      return Packet(
        header: header,
        headerSize: offset - offsetBackup,
        payload: payload,
        rawData: rawData,
      );
    } catch (e) {
      return null;
    }
  }

  @override
  String toString() {
    return 'RTP Version: ${header.version}, SSRC: ${header.ssrc}, Payload Type: ${header.payloadType}, '
        'Seq Number: ${header.sequenceNumber}, CSRC Count: ${header.csrc.length}, '
        'Payload Length: ${payload.length}, Marker: ${header.marker}';
  }
}
