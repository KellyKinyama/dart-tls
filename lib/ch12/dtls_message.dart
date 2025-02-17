import 'dart:typed_data';

class DTLSPlaintext {
  final int type;
  final List<int> version;
  final int epoch;
  final BigInt sequenceNumber;
  final int length;
  final List<int> fragment;

  DTLSPlaintext({
    required this.type,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
    required this.length,
    required this.fragment,
  });

  // Encoding the structure to bytes (for sending)
  List<int> encode() {
    var result = <int>[];

    result.addAll(Uint8List.fromList([type])); // ContentType
    result.addAll(version); // ProtocolVersion (2 bytes)
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, epoch)); // Epoch
    result.addAll(Uint8List(6)..buffer.asByteData().setUint64(0, sequenceNumber.toInt())); // Sequence Number
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, length)); // Length
    result.addAll(fragment); // Fragment data

    return result;
  }
}

class DTLSCompressed {
  final int type;
  final List<int> version;
  final int epoch;
  final BigInt sequenceNumber;
  final int length;
  final List<int> fragment;

  DTLSCompressed({
    required this.type,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
    required this.length,
    required this.fragment,
  });

  List<int> encode() {
    var result = <int>[];

    result.addAll(Uint8List.fromList([type])); // ContentType
    result.addAll(version); // ProtocolVersion (2 bytes)
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, epoch)); // Epoch
    result.addAll(Uint8List(6)..buffer.asByteData().setUint64(0, sequenceNumber.toInt())); // Sequence Number
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, length)); // Length
    result.addAll(fragment); // Fragment data

    return result;
  }
}

class DTLSCiphertext {
  final int type;
  final List<int> version;
  final int epoch;
  final BigInt sequenceNumber;
  final int length;
  final List<int> fragment;

  DTLSCiphertext({
    required this.type,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
    required this.length,
    required this.fragment,
  });

  List<int> encode() {
    var result = <int>[];

    result.addAll(Uint8List.fromList([type])); // ContentType
    result.addAll(version); // ProtocolVersion (2 bytes)
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, epoch)); // Epoch
    result.addAll(Uint8List(6)..buffer.asByteData().setUint64(0, sequenceNumber.toInt())); // Sequence Number
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, length)); // Length
    result.addAll(fragment); // Fragment data

    return result;
  }
}

class Handshake {
  final int msgType;
  final int length;
  final int messageSeq;
  final int fragmentOffset;
  final int fragmentLength;
  final dynamic body; // The body depends on the message type

  Handshake({
    required this.msgType,
    required this.length,
    required this.messageSeq,
    required this.fragmentOffset,
    required this.fragmentLength,
    required this.body,
  });

  List<int> encode() {
    var result = <int>[];

    result.addAll(Uint8List.fromList([msgType])); // HandshakeType
    result.addAll(Uint8List(3)..buffer.asByteData().setUint24(0, length)); // Length (24-bit)
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, messageSeq)); // Message Sequence
    result.addAll(Uint8List(3)..buffer.asByteData().setUint24(0, fragmentOffset)); // Fragment Offset
    result.addAll(Uint8List(3)..buffer.asByteData().setUint24(0, fragmentLength)); // Fragment Length

    // Encoding the body based on the message type (Example: ClientHello)
    if (body is ClientHello) {
      result.addAll(body.encode());
    }
    // Additional cases for other message types can be added as needed

    return result;
  }
}

class ClientHello {
  final List<int> clientVersion;
  final List<int> random;
  final List<int> sessionId;
  final List<int> cookie;
  final List<int> cipherSuites;
  final List<int> compressionMethods;

  ClientHello({
    required this.clientVersion,
    required this.random,
    required this.sessionId,
    required this.cookie,
    required this.cipherSuites,
    required this.compressionMethods,
  });

  List<int> encode() {
    var result = <int>[];

    result.addAll(clientVersion); // ProtocolVersion (2 bytes)
    result.addAll(random); // Random data
    result.addAll(sessionId); // Session ID
    result.addAll(Uint8List(1)..buffer.asByteData().setUint8(0, cookie.length)); // Cookie length
    result.addAll(cookie); // Cookie
    result.addAll(Uint8List(2)..buffer.asByteData().setUint16(0, cipherSuites.length)); // Cipher Suites length
    result.addAll(cipherSuites); // Cipher Suites
    result.addAll(Uint8List(1)..buffer.asByteData().setUint8(0, compressionMethods.length)); // Compression Methods length
    result.addAll(compressionMethods); // Compression Methods

    return result;
  }
}

class HelloVerifyRequest {
  final List<int> serverVersion;
  final List<int> cookie;

  HelloVerifyRequest({
    required this.serverVersion,
    required this.cookie,
  });

  List<int> encode() {
    var result = <int>[];

    result.addAll(serverVersion); // Server Version
    result.addAll(Uint8List(1)..buffer.asByteData().setUint8(0, cookie.length)); // Cookie length
    result.addAll(cookie); // Cookie

    return result;
  }
}

void main() {
  // Test encoding a ClientHello message
  final clientHello = ClientHello(
    clientVersion: [0x03, 0x03], // TLS 1.2
    random: List<int>.generate(32, (index) => index),
    sessionId: [],
    cookie: [0x12, 0x34],
    cipherSuites: [0x00, 0x2F, 0x00, 0x35],
    compressionMethods: [0x00],
  );

  final handshake = Handshake(
    msgType: 1, // client_hello
    length: 100, // Example length
    messageSeq: 0,
    fragmentOffset: 0,
    fragmentLength: 100,
    body: clientHello,
  );

  final encodedHandshake = handshake.encode();
  print('Encoded Handshake: $encodedHandshake');
}
