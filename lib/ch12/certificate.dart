import 'dart:typed_data';

class Certificate {
  // A list of certificates in ASN.1 format
  final List<Uint8List> certificateList;

  Certificate(this.certificateList);

  // Decodes the Certificate message from a byte array
  static Certificate decodeFrom(Uint8List data) {
    int length = data.length;
    if (length < 3) {
      throw FormatException('Insufficient data for Certificate message');
    }

    List<Uint8List> certList = [];
    int index = 0;
    while (index < length) {
      int certLength =
          (data[index] << 16) | (data[index + 1] << 8) | data[index + 2];
      index += 3;

      if (index + certLength > length) {
        throw FormatException('Invalid certificate length');
      }

      Uint8List cert = data.sublist(index, index + certLength);
      certList.add(cert);
      index += certLength;
    }

    return Certificate(certList);
  }

  // Encodes the Certificate message to a byte array
  Uint8List encodeTo() {
    List<int> encoded = [];
    for (Uint8List cert in certificateList) {
      // Adding the length prefix
      encoded.add((cert.length >> 16) & 0xFF);
      encoded.add((cert.length >> 8) & 0xFF);
      encoded.add(cert.length & 0xFF);
      encoded.addAll(cert);
    }
    return Uint8List.fromList(encoded);
  }

  @override
  String toString() {
    return 'Certificate(${certificateList.length} certificates)';
  }
}

void main() {
  // Example usage: encoding and decoding the Certificate message
  List<Uint8List> certs = [
    Uint8List.fromList([
      0x30,
      0x82,
      0x01,
      0x0A,
      0x30,
      0x82,
      0x01,
      0x06
    ]), // Example certificate 1
    Uint8List.fromList([
      0x30,
      0x82,
      0x01,
      0x0A,
      0x30,
      0x82,
      0x01,
      0x06
    ]) // Example certificate 2
  ];

  Certificate originalCertificate = Certificate(certs);
  Uint8List encoded = originalCertificate.encodeTo();
  print('Encoded Certificate: $encoded');

  Certificate decodedCertificate = Certificate.decodeFrom(encoded);
  print('Decoded Certificate: $decodedCertificate');
}
