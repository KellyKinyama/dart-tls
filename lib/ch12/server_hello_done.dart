class ServerHelloDone {
  // Since this message has no fields, it's just a marker.

  // Encode the ServerHelloDone message to a byte array (empty)
  Uint8List encodeTo() {
    return Uint8List(0); // No data to encode
  }

  // Decode the ServerHelloDone message from a byte array (expecting empty data)
  static ServerHelloDone decodeFrom(Uint8List data) {
    if (data.isNotEmpty) {
      throw FormatException('ServerHelloDone message must be empty');
    }
    return ServerHelloDone(); // Return an instance of ServerHelloDone
  }

  @override
  String toString() {
    return 'ServerHelloDone()'; // Representation of the empty message
  }
}

void main() {
  // Example: Encode and Decode ServerHelloDone
  var serverHelloDone = ServerHelloDone();

  // Encoding the message (results in an empty byte array)
  Uint8List encoded = serverHelloDone.encodeTo();
  print('Encoded ServerHelloDone: $encoded'); // []

  // Decoding the message (expects an empty byte array)
  try {
    ServerHelloDone decoded = ServerHelloDone.decodeFrom(encoded);
    print('Decoded ServerHelloDone: $decoded');
  } catch (e) {
    print('Error decoding ServerHelloDone: $e');
  }
}
