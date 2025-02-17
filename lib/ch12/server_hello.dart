import 'dart:typed_data';

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion(this.major, this.minor);

  Uint8List encodeTo() {
    final data = ByteData(2);
    data.setUint8(0, major);
    data.setUint8(1, minor);
    return data.buffer.asUint8List();
  }

  static ProtocolVersion decodeFrom(Uint8List data) {
    if (data.length != 2) {
      throw FormatException('Invalid ProtocolVersion data');
    }
    final major = data[0];
    final minor = data[1];
    return ProtocolVersion(major, minor);
  }
}

class Random {
  final Uint8List bytes;

  Random(this.bytes);

  Uint8List encodeTo() => bytes;

  static Random decodeFrom(Uint8List data) {
    return Random(data);
  }
}

class SessionID {
  final Uint8List id;

  SessionID(this.id);

  Uint8List encodeTo() => id;

  static SessionID decodeFrom(Uint8List data) {
    return SessionID(data);
  }
}

class CipherSuite {
  final int suite;

  CipherSuite(this.suite);

  Uint8List encodeTo() {
    final data = ByteData(2);
    data.setUint16(0, suite, Endian.big);
    return data.buffer.asUint8List();
  }

  static CipherSuite decodeFrom(Uint8List data) {
    if (data.length != 2) {
      throw FormatException('Invalid CipherSuite data');
    }
    final suite = ByteData.sublistView(data).getUint16(0, Endian.big);
    return CipherSuite(suite);
  }
}

class CompressionMethod {
  final int method;

  CompressionMethod(this.method);

  Uint8List encodeTo() {
    final data = ByteData(1);
    data.setUint8(0, method);
    return data.buffer.asUint8List();
  }

  static CompressionMethod decodeFrom(Uint8List data) {
    if (data.length != 1) {
      throw FormatException('Invalid CompressionMethod data');
    }
    final method = data[0];
    return CompressionMethod(method);
  }
}

class Extension {
  final int extensionType;
  final Uint8List extensionData;

  Extension(this.extensionType, this.extensionData);

  Uint8List encodeTo() {
    final buffer = BytesBuilder();
    buffer.add(Uint8List(2)
      ..buffer.asByteData().setUint16(0, extensionType, Endian.big));
    buffer.add(extensionData);
    return buffer.toBytes();
  }

  static Extension decodeFrom(Uint8List data) {
    if (data.length < 2) {
      throw FormatException('Invalid Extension data');
    }
    final extensionType = ByteData.sublistView(data).getUint16(0, Endian.big);
    final extensionData = data.sublist(2);
    return Extension(extensionType, extensionData);
  }
}

class ServerHello {
  final ProtocolVersion serverVersion;
  final Random random;
  final SessionID sessionID;
  final CipherSuite cipherSuite;
  final CompressionMethod compressionMethod;
  final List<Extension> extensions;

  ServerHello({
    required this.serverVersion,
    required this.random,
    required this.sessionID,
    required this.cipherSuite,
    required this.compressionMethod,
    required this.extensions,
  });

  Uint8List encodeTo() {
    final buffer = BytesBuilder();
    buffer.add(serverVersion.encodeTo());
    buffer.add(random.encodeTo());
    buffer.add(sessionID.encodeTo());
    buffer.add(cipherSuite.encodeTo());
    buffer.add(compressionMethod.encodeTo());

    if (extensions.isNotEmpty) {
      final extensionsData =
          extensions.expand((ext) => ext.encodeTo()).toList();
      buffer.add(Uint8List(2)
        ..buffer.asByteData().setUint16(0, extensionsData.length, Endian.big));
      buffer.addAll(extensionsData);
    }

    return buffer.toBytes();
  }

  static ServerHello decodeFrom(Uint8List data) {
    if (data.length < 7) {
      throw FormatException('Invalid ServerHello data');
    }
    final serverVersion = ProtocolVersion.decodeFrom(data.sublist(0, 2));
    final random = Random.decodeFrom(data.sublist(2, 34));
    final sessionID = SessionID.decodeFrom(data.sublist(34, 50));
    final cipherSuite = CipherSuite.decodeFrom(data.sublist(50, 52));
    final compressionMethod =
        CompressionMethod.decodeFrom(data.sublist(52, 53));

    int offset = 53;
    final extensionsLength =
        ByteData.sublistView(data).getUint16(offset, Endian.big);
    offset += 2;

    final extensions = <Extension>[];
    while (offset < extensionsLength + 53) {
      final ext = Extension.decodeFrom(data.sublist(offset));
      extensions.add(ext);
      offset += ext.encodeTo().length;
    }

    return ServerHello(
      serverVersion: serverVersion,
      random: random,
      sessionID: sessionID,
      cipherSuite: cipherSuite,
      compressionMethod: compressionMethod,
      extensions: extensions,
    );
  }
}

void main() {
  final serverHello = ServerHello(
    serverVersion: ProtocolVersion(3, 3),
    random: Random(Uint8List(32)),
    sessionID: SessionID(Uint8List(32)),
    cipherSuite: CipherSuite(0x0035), // example cipher suite
    compressionMethod: CompressionMethod(0), // no compression
    extensions: [],
  );

  final encoded = serverHello.encodeTo();
  final decoded = ServerHello.decodeFrom(encoded);

  print('Decoded ServerHello:');
  print(
      'Version: ${decoded.serverVersion.major}.${decoded.serverVersion.minor}');
  print('CipherSuite: ${decoded.cipherSuite.suite}');
}
