import 'dart:typed_data';

import 'package:dart_tls/ch09/dtls_state.dart';
import 'package:dart_tls/ch09/enums.dart';
import 'package:dart_tls/ch09/handshake/handshake.dart';

import 'tls_random.dart';

class HandshakeContext {
  Flight flight = Flight.Flight0;

  late Uint8List serverKeySignature;

  late DTLSState dTLSState;

  late ProtocolVersion protocolVersion;

  late Uint8List cookie;

  late int cipherSuite;

  late TlsRandom clientRandom;

  late TlsRandom serverRandom;

  late Uint8List serverPublicKey;

  late Uint8List serverPrivateKey;

  late int curve;

  late Uint8List expectedFingerprintHash;

  List<Uint8List> clientCertificates = [];

  var clientKeyExchangePublic;

  bool isCipherSuiteInitialized = false;

  Map<HandshakeType, Uint8List> HandshakeMessagesReceived = {};

  Map<HandshakeType, Uint8List> HandshakeMessagesSent = {};

  late Uint8List serverMasterSecret;

  int serverSequenceNumber = 0;

  int serverHandshakeSequenceNumber = 0;

  void increaseServerSequence() {
    serverSequenceNumber++;
  }

  void increaseServerHandshakeSequence() {
    serverHandshakeSequenceNumber++;
  }

  int serverEpoch = 0;

  late bool UseExtendedMasterSecret;

  late int srtpProtectionProfile;
  void increaseServerEpoch() {
    serverEpoch++;
  }
}
