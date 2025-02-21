// import 'dart:io';
import 'dart:typed_data';

// import 'package:dart_tls/ch09/handshaker/aes_gcm_128_sha_256.dart';

import 'package:dart_tls/ch09/handshake/finished.dart';
import 'package:dart_tls/ch09/handshake/handshake.dart';
import 'package:dart_tls/ch09/record_layer_header.dart';
import 'package:hex/hex.dart';

import '../../ch09/cert_utils.dart';
import '../../ch09/handshake/handshake_context.dart';
import '../../ch09/handshake/handshake_header.dart';
import '../../ch09/key_exchange_algorithm.dart';

// void testPreMasterSecretP256() {
//   final expected = generatePreMasterSecret(
//     pub,
//     priv,
//   );
//   //expect(expected).toEqual(sec);
//   print("generatePreMasterSecret:    $expected");
//   print("Wanted PreMasterSecret:     $sec");
// }

Future<void> main() async {
  // testPreMasterSecretP256();
  // var keys = generateP256Keys();
  // print(keys);

  HandshakeContext server = HandshakeContext();

  HandshakeContext client = HandshakeContext();

  server.clientKeyExchangePublic = clientPub;
  server.serverPrivateKey = serverPriv;
  Uint8List serverPreMasterSecret = generatePreMasterSecret(
      server.clientKeyExchangePublic, server.serverPrivateKey);
  server.serverMasterSecret =
      generateMasterSecret(serverPreMasterSecret, clientRandom, serverRandom);

  client.clientKeyExchangePublic = serverPub;
  client.serverPrivateKey = clientPriv;
  Uint8List clientPreMasterSecret = generatePreMasterSecret(
      client.clientKeyExchangePublic, client.serverPrivateKey);
  client.serverMasterSecret =
      generateMasterSecret(clientPreMasterSecret, clientRandom, serverRandom);

  print("Server pre master secret:    ${serverPreMasterSecret}");
  print("Client pre premaster secret: ${clientPreMasterSecret}");

  print("Server master secret:    ${client.serverMasterSecret}");
  print("Client premaster secret: ${server.serverMasterSecret}");

  final serverGcm =
      await initGCM(server.serverMasterSecret, clientRandom, serverRandom);
  // if err != nil {
  // 	return err
  // }
  server.gcm = serverGcm;
  server.isCipherSuiteInitialized = true;

  final clientGcm =
      await initGCM(client.serverMasterSecret, clientRandom, serverRandom);
  // if err != nil {
  // 	return err
  // }
  client.gcm = clientGcm;
  // client.isCipherSuiteInitialized = true;

  final (finishedUnMarshalled, _, _) =
      Finished.unmarshal(finished, 0, finished.length);

  final finishedMarshalled = constractMessage(server, finishedUnMarshalled);

  final (header, _, _) = RecordLayerHeader.unmarshal(
      Uint8List.fromList(finishedMarshalled),
      offset: 0,
      arrayLen: finishedMarshalled.length);

  // final raw = HEX.decode("c2c64f7508209fe9d6418302fb26b7a07a");
  final encryptedBytes =
      await serverGcm.encrypt(header, Uint8List.fromList(finishedMarshalled));
  final decryptedBytes =
      await clientGcm.decrypt(Uint8List.fromList(encryptedBytes));
  print("decrypted: $decryptedBytes");

  print("Finished marshalled: $finishedMarshalled");
  // print(
  // "Unmarshalling finished: ${finishedMarshalled.marshal()}, length: ${finished.length}");
  print("Expected:            $decryptedBytes");
}

List<int> constractMessage(HandshakeContext context, dynamic message) {
  // print("object type: ${message.runtimeType}");
  final Uint8List encodedMessageBody = message.marshal();
  final encodedMessage = BytesBuilder();
  HandshakeHeader handshakeHeader;
  switch (message.getContentType()) {
    case ContentType.content_handshake:
      // print("message type: ${message.getContentType()}");
      handshakeHeader = HandshakeHeader(
          handshakeType: message.getHandshakeType(),
          length: Uint24.fromUInt32(encodedMessageBody.length),
          messageSequence: context.serverHandshakeSequenceNumber,
          fragmentOffset: Uint24.fromUInt32(0),
          fragmentLength: Uint24.fromUInt32(encodedMessageBody.length));
      context.increaseServerHandshakeSequence();
      final encodedHandshakeHeader = handshakeHeader.marshal();
      encodedMessage.add(encodedHandshakeHeader);
      encodedMessage.add(encodedMessageBody);
  }

  final header = RecordLayerHeader(
      contentType: message.getContentType(),
      protocolVersion: ProtocolVersion(254, 253),
      epoch: context.serverEpoch,
      sequenceNumber: context.serverSequenceNumber,
      contentLen: encodedMessage.toBytes().length);

  final encodedHeader = header.marshal();
  final messageToSend = encodedHeader + encodedMessage.toBytes();
  context.increaseServerSequence();
  return messageToSend;
}

final finished = Uint8List.fromList([
  0x01,
  0x01,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x08,
  0x09,
  0x0a,
  0x0b,
  0x0c,
  0x0d,
  0x0e,
  0x0f,
]);

final serverPub = Uint8List.fromList([
  4,
  28,
  229,
  193,
  94,
  12,
  144,
  126,
  3,
  148,
  196,
  26,
  29,
  138,
  70,
  66,
  8,
  51,
  160,
  46,
  9,
  63,
  177,
  154,
  102,
  185,
  24,
  25,
  42,
  202,
  91,
  193,
  79,
  20,
  126,
  16,
  109,
  252,
  12,
  209,
  217,
  251,
  109,
  94,
  137,
  201,
  92,
  218,
  254,
  199,
  49,
  32,
  108,
  169,
  55,
  64,
  122,
  150,
  152,
  212,
  109,
  103,
  153,
  148,
  196,
]);
final serverPriv = Uint8List.fromList([
  146,
  127,
  145,
  226,
  6,
  177,
  52,
  198,
  57,
  194,
  77,
  99,
  125,
  93,
  169,
  243,
  199,
  107,
  15,
  185,
  97,
  48,
  206,
  118,
  193,
  86,
  180,
  22,
  202,
  132,
  88,
  220,
]);
final sec = Uint8List.fromList([
  140,
  159,
  40,
  70,
  230,
  12,
  161,
  28,
  51,
  160,
  233,
  64,
  119,
  185,
  161,
  38,
  201,
  230,
  39,
  126,
  124,
  187,
  64,
  78,
  247,
  129,
  217,
  75,
  242,
  136,
  75,
  188,
]);
final clientRandom = Uint8List.fromList([
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x08,
  0x09,
  0x0a,
  0x0b,
  0x0c,
  0x0d,
  0x0e,
  0x0f,
  0x10,
  0x11,
  0x12,
  0x13,
  0x14,
  0x15,
  0x16,
  0x17,
  0x18,
  0x19,
  0x1a,
  0x1b,
  0x1c,
  0x1d,
  0x1e,
  0x1f,
]);
final serverRandom = Uint8List.fromList([
  0x70,
  0x71,
  0x72,
  0x73,
  0x74,
  0x75,
  0x76,
  0x77,
  0x78,
  0x79,
  0x7a,
  0x7b,
  0x7c,
  0x7d,
  0x7e,
  0x7f,
  0x80,
  0x81,
  0x82,
  0x83,
  0x84,
  0x85,
  0x86,
  0x87,
  0x88,
  0x89,
  0x8a,
  0x8b,
  0x8c,
  0x8d,
  0x8e,
  0x8f,
]);

final clientPriv = Uint8List.fromList([
  162,
  86,
  73,
  72,
  50,
  31,
  76,
  121,
  108,
  6,
  119,
  239,
  2,
  210,
  182,
  252,
  203,
  43,
  167,
  90,
  2,
  221,
  76,
  121,
  153,
  37,
  52,
  101,
  35,
  120,
  190,
  253
]);
final clientPub = Uint8List.fromList([
  4,
  254,
  167,
  164,
  160,
  98,
  84,
  123,
  230,
  152,
  16,
  94,
  0,
  221,
  79,
  69,
  70,
  205,
  88,
  2,
  159,
  214,
  149,
  220,
  86,
  243,
  87,
  75,
  41,
  80,
  2,
  239,
  25,
  185,
  214,
  62,
  229,
  61,
  95,
  37,
  136,
  206,
  229,
  237,
  252,
  54,
  38,
  5,
  58,
  170,
  146,
  100,
  210,
  64,
  133,
  245,
  193,
  145,
  72,
  192,
  126,
  241,
  3,
  153,
  118
]);
