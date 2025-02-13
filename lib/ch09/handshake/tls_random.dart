import 'dart:math';
import 'dart:typed_data';

const int RANDOM_BYTES_LENGTH = 28;
const int HANDSHAKE_RANDOM_LENGTH = RANDOM_BYTES_LENGTH + 4;

class TlsRandom {
  DateTime gmt_unix_time;
  List<int> randomBytes = List.filled(28, 0);
  TlsRandom(this.gmt_unix_time, this.randomBytes) {
    if (randomBytes.length != RANDOM_BYTES_LENGTH) {
      throw "Invalid random bytes length: ${randomBytes.length}";
    }
  }

  factory TlsRandom.fromBytes(Uint8List bytes, int offset) {
    final secs = ByteData.sublistView(bytes, 0, 4).getUint32(0, Endian.big);
    final gmtUnixTime =
        DateTime.fromMillisecondsSinceEpoch(secs * 1000, isUtc: true);

    offset += 4;
    final random_bytes = bytes.sublist(offset, offset + RANDOM_BYTES_LENGTH);
    offset += RANDOM_BYTES_LENGTH;

    return TlsRandom(gmtUnixTime, random_bytes);
  }

  factory TlsRandom.defaultInstance() {
    return TlsRandom(
      DateTime.now(),
      List.filled(RANDOM_BYTES_LENGTH, 0),
    );
  }

  /// Marshal the object into bytes
  Uint8List marshal() {
    final bb = BytesBuilder();
    int secs = gmt_unix_time.millisecondsSinceEpoch ~/ 1000;
    bb.add(Uint8List(4)..buffer.asByteData().setUint32(0, secs, Endian.big));

    if (randomBytes.length != RANDOM_BYTES_LENGTH) {
      throw "Invalid random bytes length: ${randomBytes.length}";
    }
    bb.add(Uint8List.fromList(randomBytes));
    return bb.toBytes();
  }

  /// Unmarshal the object from bytes
  static TlsRandom unmarshal(Uint8List bytes, int offset, int arrayLen) {
    // if (bytes.length != HANDSHAKE_RANDOM_LENGTH) {
    //   throw FormatException("Invalid HandshakeRandom length");
    // }

    final secs = ByteData.sublistView(bytes, offset, offset + 4)
        .getUint32(0, Endian.big);

    offset = offset + 4;
    final gmtUnixTime =
        DateTime.fromMillisecondsSinceEpoch(secs * 1000, isUtc: true);
    final randomBytes = bytes.sublist(offset, offset + RANDOM_BYTES_LENGTH);

    if (randomBytes.length != RANDOM_BYTES_LENGTH) {
      throw "Invalid random bytes length: ${randomBytes.length}";
    }

    return TlsRandom(
      gmtUnixTime,
      randomBytes,
    );
  }

  /// Populate the random bytes and set the current time
  void populate() {
    gmt_unix_time = DateTime.now().toUtc();
    final rng = Random.secure();
    randomBytes = List.generate(RANDOM_BYTES_LENGTH, (_) => rng.nextInt(256));
  }
}
