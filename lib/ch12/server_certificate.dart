import 'dart:typed_data';

class Certificate {
  final List<Uint8List> certificateList;

  Certificate(this.certificateList);

  // Encode the Certificate message by concatenating all certificates in the list
  Uint8List encodeTo() {
    // Concatenate certificates in the certificate list
    int totalLength = certificateList.fold(0, (sum, cert) => sum + cert.length);
    final encoded = Uint8List(totalLength);
    int offset = 0;
    for (var cert in certificateList) {
      encoded.setRange(offset, offset + cert.length, cert);
      offset += cert.length;
    }
    return encoded;
  }

  // Decode the Certificate message from a byte array
  static Certificate decodeFrom(Uint8List data) {
    int offset = 0;
    List<Uint8List> certificates = [];
    while (offset < data.length) {
      // Extract certificate length (big-endian)
      int certLength = (data[offset] << 8) + data[offset + 1];
      offset += 2;
      certificates.add(data.sublist(offset, offset + certLength));
      offset += certLength;
    }
    return Certificate(certificates);
  }

  @override
  String toString() {
    return 'Certificate(certificateList: ${certificateList.length} certificates)';
  }
}

void main() {
  // Example: Encode and Decode Server Certificate
  List<Uint8List> certs = [
    Uint8List.fromList(
        [0x30, 0x82, 0x01, 0x0A]), // Fake certificate for example purposes
    Uint8List.fromList(
        [0x30, 0x82, 0x01, 0x0B]) // Fake certificate for example purposes
  ];

  // Create a Certificate object
  var certificate = Certificate(certs);

  // Encoding the certificate (serialize the list of certificates)
  Uint8List encoded = certificate.encodeTo();
  print('Encoded Certificate: $encoded');

  // Decoding the certificate back to the Certificate object
  try {
    Certificate decoded = Certificate.decodeFrom(encoded);
    print('Decoded Certificate: $decoded');
  } catch (e) {
    print('Error decoding Certificate: $e');
  }
}
