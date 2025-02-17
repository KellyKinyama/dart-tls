import 'dart:typed_data';

class ClientCertificate {
  final List<Uint8List> certificateList;

  ClientCertificate(this.certificateList);

  // Encode the Client Certificate message (serialize the list of certificates)
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

  // Decode the Client Certificate message from a byte array
  static ClientCertificate decodeFrom(Uint8List data) {
    int offset = 0;
    List<Uint8List> certificates = [];
    while (offset < data.length) {
      // Extract certificate length (big-endian)
      int certLength = (data[offset] << 8) + data[offset + 1];
      offset += 2;
      certificates.add(data.sublist(offset, offset + certLength));
      offset += certLength;
    }
    return ClientCertificate(certificates);
  }

  @override
  String toString() {
    return 'ClientCertificate(certificateList: ${certificateList.length} certificates)';
  }
}

void main() {
  // Example: Encode and Decode Client Certificate
  List<Uint8List> certs = [
    Uint8List.fromList([0x30, 0x82, 0x01, 0x0A]), // Fake certificate for example purposes
    Uint8List.fromList([0x30, 0x82, 0x01, 0x0B])  // Fake certificate for example purposes
  ];
  
  // Create a ClientCertificate object
  var clientCertificate = ClientCertificate(certs);

  // Encoding the certificate (serialize the list of certificates)
  Uint8List encoded = clientCertificate.encodeTo();
  print('Encoded Client Certificate: $encoded');

  // Decoding the certificate back to the ClientCertificate object
  try {
    ClientCertificate decoded = ClientCertificate.decodeFrom(encoded);
    print('Decoded Client Certificate: $decoded');
  } catch (e) {
    print('Error decoding Client Certificate: $e');
  }
}
