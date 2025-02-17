import 'dart:typed_data';

enum ClientCertificateType {
  rsa_sign(1),
  dss_sign(2),
  rsa_fixed_dh(3),
  dss_fixed_dh(4),
  rsa_ephemeral_dh_RESERVED(5),
  dss_ephemeral_dh_RESERVED(6),
  fortezza_dms_RESERVED(20),
  unknown(255);

  final int value;
  const ClientCertificateType(this.value);

  // Decode a ClientCertificateType from an integer
  static ClientCertificateType fromInt(int value) {
    return ClientCertificateType.values.firstWhere((e) => e.value == value,
        orElse: () => ClientCertificateType.unknown);
  }
}

class SignatureAndHashAlgorithm {
  final int signature;
  final int hashAlgorithm;

  SignatureAndHashAlgorithm(this.signature, this.hashAlgorithm);

  // Decodes SignatureAndHashAlgorithm from a byte array
  static SignatureAndHashAlgorithm decodeFrom(Uint8List data) {
    if (data.length != 2) {
      throw FormatException('Invalid SignatureAndHashAlgorithm data length');
    }
    return SignatureAndHashAlgorithm(data[0], data[1]);
  }

  // Encodes SignatureAndHashAlgorithm to a byte array
  Uint8List encodeTo() {
    return Uint8List.fromList([signature, hashAlgorithm]);
  }

  @override
  String toString() {
    return 'SignatureAndHashAlgorithm(signature: $signature, hashAlgorithm: $hashAlgorithm)';
  }
}

class CertificateRequest {
  final List<ClientCertificateType> certificateTypes;
  final List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms;
  final List<Uint8List> certificateAuthorities; // List of DistinguishedNames

  CertificateRequest({
    required this.certificateTypes,
    required this.supportedSignatureAlgorithms,
    required this.certificateAuthorities,
  });

  // Decodes a CertificateRequest message from a byte array
  static CertificateRequest decodeFrom(Uint8List data) {
    int index = 0;

    // Decode certificate_types
    int certificateTypesLength = data[index++];
    List<ClientCertificateType> certificateTypes = [];
    for (int i = 0; i < certificateTypesLength; i++) {
      certificateTypes.add(ClientCertificateType.fromInt(data[index++]));
    }

    // Decode supported_signature_algorithms
    int supportedSignatureAlgorithmsLength =
        (data[index] << 8) | data[index + 1];
    index += 2;
    List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = [];
    for (int i = 0; i < supportedSignatureAlgorithmsLength; i++) {
      supportedSignatureAlgorithms.add(
          SignatureAndHashAlgorithm.decodeFrom(data.sublist(index, index + 2)));
      index += 2;
    }

    // Decode certificate_authorities
    int certificateAuthoritiesLength = (data[index] << 8) | data[index + 1];
    index += 2;
    List<Uint8List> certificateAuthorities = [];
    for (int i = 0; i < certificateAuthoritiesLength; i++) {
      int dnLength = (data[index] << 8) | data[index + 1];
      index += 2;
      certificateAuthorities.add(data.sublist(index, index + dnLength));
      index += dnLength;
    }

    return CertificateRequest(
      certificateTypes: certificateTypes,
      supportedSignatureAlgorithms: supportedSignatureAlgorithms,
      certificateAuthorities: certificateAuthorities,
    );
  }

  // Encodes a CertificateRequest message to a byte array
  Uint8List encodeTo() {
    List<int> encoded = [];

    // Encode certificate_types
    encoded.add(certificateTypes.length);
    for (var type in certificateTypes) {
      encoded.add(type.value);
    }

    // Encode supported_signature_algorithms
    encoded.addAll(_encodeLength(supportedSignatureAlgorithms.length));
    for (var algorithm in supportedSignatureAlgorithms) {
      encoded.addAll(algorithm.encodeTo());
    }

    // Encode certificate_authorities
    encoded.addAll(_encodeLength(certificateAuthorities.length));
    for (var dn in certificateAuthorities) {
      encoded.addAll(_encodeLength(dn.length));
      encoded.addAll(dn);
    }

    return Uint8List.fromList(encoded);
  }

  List<int> _encodeLength(int length) {
    return [
      (length >> 8) & 0xFF,
      length & 0xFF,
    ];
  }

  @override
  String toString() {
    return 'CertificateRequest(certificateTypes: $certificateTypes, supportedSignatureAlgorithms: $supportedSignatureAlgorithms, certificateAuthorities: ${certificateAuthorities.length})';
  }
}

void main() {
  // Example: create and encode a CertificateRequest
  var certificateTypes = [
    ClientCertificateType.rsa_sign,
    ClientCertificateType.dss_sign
  ];
  var signatureAlgorithms = [
    SignatureAndHashAlgorithm(1, 1), // Example: RSA with SHA-1
    SignatureAndHashAlgorithm(2, 1) // Example: DSA with SHA-1
  ];
  var certificateAuthorities = [
    Uint8List.fromList(
        [0x30, 0x82]) // Example DistinguishedName (in DER format)
  ];

  var certRequest = CertificateRequest(
    certificateTypes: certificateTypes,
    supportedSignatureAlgorithms: signatureAlgorithms,
    certificateAuthorities: certificateAuthorities,
  );

  Uint8List encoded = certRequest.encodeTo();
  print('Encoded CertificateRequest: $encoded');

  CertificateRequest decoded = CertificateRequest.decodeFrom(encoded);
  print('Decoded CertificateRequest: $decoded');
}
