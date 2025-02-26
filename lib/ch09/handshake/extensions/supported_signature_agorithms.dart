import 'dart:typed_data';
import 'dart:io';

const EXTENSION_SUPPORTED_SIGNATURE_ALGORITHMS_HEADER_SIZE = 6;

enum ExtensionValue { supportedSignatureAlgorithms }

enum SignatureHashAlgorithmType {
  sha256,
  sha384,
  sha512
} // Example, add more as needed

class SignatureHashAlgorithm {
  final SignatureHashAlgorithmType hash;
  final SignatureHashAlgorithmType signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});
}

class ExtensionSupportedSignatureAlgorithms {
  final List<SignatureHashAlgorithm> signatureHashAlgorithms;

  ExtensionSupportedSignatureAlgorithms(
      {required this.signatureHashAlgorithms});

  int get size {
    return 2 + 2 + signatureHashAlgorithms.length * 2;
  }

  ExtensionValue extensionValue() {
    return ExtensionValue.supportedSignatureAlgorithms;
  }

  Future<void> marshal(ByteData writer) async {
    writer.setUint16(
        0, (2 + 2 * signatureHashAlgorithms.length) & 0xFFFF, Endian.big);
    writer.setUint16(
        2, (2 * signatureHashAlgorithms.length) & 0xFFFF, Endian.big);

    int offset = 4;
    for (var algorithm in signatureHashAlgorithms) {
      writer.setUint8(offset, algorithm.hash.index);
      writer.setUint8(offset + 1, algorithm.signature.index);
      offset += 2;
    }

    await writer.buffer.asUint8List();
  }

  static Future<ExtensionSupportedSignatureAlgorithms> unmarshal(
      ByteData reader) async {
    reader.getUint16(0, Endian.big); // Skip the first 2 bytes

    int algorithmCount = reader.getUint16(2, Endian.big) ~/ 2;
    List<SignatureHashAlgorithm> signatureHashAlgorithms = [];

    int offset = 4;
    for (int i = 0; i < algorithmCount; i++) {
      var hash = SignatureHashAlgorithmType.values[reader.getUint8(offset)];
      var signature =
          SignatureHashAlgorithmType.values[reader.getUint8(offset + 1)];
      signatureHashAlgorithms
          .add(SignatureHashAlgorithm(hash: hash, signature: signature));
      offset += 2;
    }

    return ExtensionSupportedSignatureAlgorithms(
        signatureHashAlgorithms: signatureHashAlgorithms);
  }
}

void main() async {
  // Example usage
  var extension =
      ExtensionSupportedSignatureAlgorithms(signatureHashAlgorithms: [
    SignatureHashAlgorithm(
        hash: SignatureHashAlgorithmType.sha256,
        signature: SignatureHashAlgorithmType.sha256),
    SignatureHashAlgorithm(
        hash: SignatureHashAlgorithmType.sha384,
        signature: SignatureHashAlgorithmType.sha384),
  ]);

  // Create a ByteData to simulate the writer
  var writer = ByteData(extension.size);

  // Marshal the object
  await extension.marshal(writer);

  // Unmarshal the object from ByteData (reader simulation)
  var unmarshalledExtension =
      await ExtensionSupportedSignatureAlgorithms.unmarshal(writer);

  print(
      'Unmarshalled Signature Hash Algorithms: ${unmarshalledExtension.signatureHashAlgorithms}');
}
