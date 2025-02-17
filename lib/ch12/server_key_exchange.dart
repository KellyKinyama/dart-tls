import 'dart:typed_data';

enum KeyExchangeAlgorithm { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa }

class ServerDHParams {
  final Uint8List dhP; // The prime modulus
  final Uint8List dhG; // The generator
  final Uint8List dhYs; // The server's Diffie-Hellman public value (g^X mod p)

  ServerDHParams(this.dhP, this.dhG, this.dhYs);

  // Decodes the Diffie-Hellman parameters from a byte array
  static ServerDHParams decodeFrom(Uint8List data) {
    if (data.length < 3) {
      throw FormatException('Insufficient data for ServerDHParams');
    }

    int index = 0;

    // dh_p length
    int pLength =
        (data[index] << 16) | (data[index + 1] << 8) | data[index + 2];
    index += 3;
    if (index + pLength > data.length)
      throw FormatException('Invalid dh_p length');
    Uint8List dhP = data.sublist(index, index + pLength);
    index += pLength;

    // dh_g length
    int gLength =
        (data[index] << 16) | (data[index + 1] << 8) | data[index + 2];
    index += 3;
    if (index + gLength > data.length)
      throw FormatException('Invalid dh_g length');
    Uint8List dhG = data.sublist(index, index + gLength);
    index += gLength;

    // dh_Ys length
    int ysLength =
        (data[index] << 16) | (data[index + 1] << 8) | data[index + 2];
    index += 3;
    if (index + ysLength > data.length)
      throw FormatException('Invalid dh_Ys length');
    Uint8List dhYs = data.sublist(index, index + ysLength);

    return ServerDHParams(dhP, dhG, dhYs);
  }

  // Encodes the Diffie-Hellman parameters to a byte array
  Uint8List encodeTo() {
    List<int> encoded = [];

    // Encode dh_p
    encoded.addAll(_encodeLength(dhP.length));
    encoded.addAll(dhP);

    // Encode dh_g
    encoded.addAll(_encodeLength(dhG.length));
    encoded.addAll(dhG);

    // Encode dh_Ys
    encoded.addAll(_encodeLength(dhYs.length));
    encoded.addAll(dhYs);

    return Uint8List.fromList(encoded);
  }

  List<int> _encodeLength(int length) {
    return [
      (length >> 16) & 0xFF,
      (length >> 8) & 0xFF,
      length & 0xFF,
    ];
  }

  @override
  String toString() {
    return 'ServerDHParams(dhP: ${dhP.length}, dhG: ${dhG.length}, dhYs: ${dhYs.length})';
  }
}

class ServerKeyExchange {
  final KeyExchangeAlgorithm keyExchangeAlgorithm;
  final ServerDHParams? params;
  final Uint8List? signedParams;

  ServerKeyExchange(this.keyExchangeAlgorithm,
      {this.params, this.signedParams});

  // Decodes the ServerKeyExchange message from a byte array
  static ServerKeyExchange decodeFrom(Uint8List data) {
    if (data.isEmpty)
      throw FormatException('Insufficient data for ServerKeyExchange');

    int index = 0;

    // Key exchange algorithm
    KeyExchangeAlgorithm keyExchangeAlgorithm =
        KeyExchangeAlgorithm.values[data[index]];
    index += 1;

    // For anonymous key exchange algorithms, only params are sent
    if (keyExchangeAlgorithm == KeyExchangeAlgorithm.dh_anon) {
      ServerDHParams params = ServerDHParams.decodeFrom(data.sublist(index));
      return ServerKeyExchange(keyExchangeAlgorithm, params: params);
    }

    // For other key exchange algorithms, check for signed parameters
    if (keyExchangeAlgorithm == KeyExchangeAlgorithm.dhe_dss ||
        keyExchangeAlgorithm == KeyExchangeAlgorithm.dhe_rsa) {
      // Extract signed parameters
      int signedParamsLength =
          (data[index] << 16) | (data[index + 1] << 8) | data[index + 2];
      index += 3;
      Uint8List signedParams = data.sublist(index, index + signedParamsLength);
      return ServerKeyExchange(keyExchangeAlgorithm,
          signedParams: signedParams);
    }

    // For non-anonymous key exchange algorithms, there's no params field
    return ServerKeyExchange(keyExchangeAlgorithm);
  }

  // Encodes the ServerKeyExchange message to a byte array
  Uint8List encodeTo() {
    List<int> encoded = [];

    // Encode key exchange algorithm
    encoded.add(KeyExchangeAlgorithm.values.indexOf(keyExchangeAlgorithm));

    if (keyExchangeAlgorithm == KeyExchangeAlgorithm.dh_anon) {
      if (params != null) {
        encoded.addAll(params!.encodeTo());
      }
    } else if (keyExchangeAlgorithm == KeyExchangeAlgorithm.dhe_dss ||
        keyExchangeAlgorithm == KeyExchangeAlgorithm.dhe_rsa) {
      if (params != null) {
        encoded.addAll(params!.encodeTo());
      }
      if (signedParams != null) {
        encoded.addAll(_encodeLength(signedParams!.length));
        encoded.addAll(signedParams!);
      }
    }

    return Uint8List.fromList(encoded);
  }

  List<int> _encodeLength(int length) {
    return [
      (length >> 16) & 0xFF,
      (length >> 8) & 0xFF,
      length & 0xFF,
    ];
  }

  @override
  String toString() {
    return 'ServerKeyExchange(keyExchangeAlgorithm: $keyExchangeAlgorithm, params: $params, signedParams: ${signedParams?.length ?? 0})';
  }
}

void main() {
  // Example: encode and decode ServerKeyExchange
  var params = ServerDHParams(Uint8List.fromList([0x00, 0x01]),
      Uint8List.fromList([0x00, 0x02]), Uint8List.fromList([0x00, 0x03]));
  var serverKeyExchange =
      ServerKeyExchange(KeyExchangeAlgorithm.dhe_rsa, params: params);

  Uint8List encoded = serverKeyExchange.encodeTo();
  print('Encoded ServerKeyExchange: $encoded');

  ServerKeyExchange decoded = ServerKeyExchange.decodeFrom(encoded);
  print('Decoded ServerKeyExchange: $decoded');
}
