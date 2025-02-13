// what is the flow of handshake messages for this cipher suite between server and client: Tls_Psk_With_Aes_128_Ccm
// ChatGPT said:
// The TLS 1.2 handshake for the cipher suite TLS_PSK_WITH_AES_128_CCM follows a simplified Pre-Shared Key (PSK) handshake flow because it does not use public-key cryptography (e.g., certificates or key exchange mechanisms like ECDHE). Instead, both the client and server use a pre-shared key (PSK) to establish a secure connection.

// 🛠 TLS 1.2 PSK Handshake Flow (TLS_PSK_WITH_AES_128_CCM)
// Client ↔ Server Handshake Message Flow
// ClientHello → (Client → Server)

// Proposes supported cipher suites, including TLS_PSK_WITH_AES_128_CCM.
// Includes a random number (ClientRandom).
// Includes a PSK identity hint (optional, tells the server which PSK to use).
// ServerHello → (Server → Client)

// Selects TLS 1.2 and TLS_PSK_WITH_AES_128_CCM as the cipher suite.
// Includes a random number (ServerRandom).
// ServerHelloDone → (Server → Client)

// Informs the client that the server's hello messages are complete.
// ClientKeyExchange → (Client → Server)

// Includes the PSK identity (which tells the server which PSK to use).
// No actual key exchange occurs (since the PSK is already shared).
// ChangeCipherSpec → (Client → Server)

// Client tells the server: "I'm switching to encrypted mode now."
// Finished → (Client → Server)

// Sends a hashed MAC (Message Authentication Code) to verify handshake integrity.
// Encrypted using the negotiated session key derived from PSK.
// ChangeCipherSpec → (Server → Client)

// Server switches to encrypted mode.
// Finished → (Server → Client)

// Server verifies handshake integrity.
// ✔️ Secure connection established! 🎉

// From this point onward, all communication is encrypted using AES-128-CCM.
// 🔍 Key Differences from Regular TLS Handshakes
// ✅ No certificate exchange (since no asymmetric cryptography is used).
// ✅ No Diffie-Hellman or ECDHE key exchange (session key is derived from PSK).
// ✅ Faster handshake (fewer messages, no expensive crypto operations).
// ✅ Lower computational cost (good for embedded devices and IoT).

// ⚠️ Security Considerations:

// The PSK must be kept secret (if compromised, anyone can decrypt the session).
// Not Forward Secret ⚠️ (if PSK is leaked, past sessions can be decrypted).
// Typically used in IoT, constrained devices, or pre-configured secure environments.
// 📌 Example Wireshark Capture of a PSK Handshake
// If you capture this handshake in Wireshark, you’ll see:

// ClientHello → ServerHello (TLS version, cipher selection)
// ClientKeyExchange (PSK Identity)
// ChangeCipherSpec & Finished
// Encrypted Application Data
// 📢 Summary
// Step	Message	Description
// 1	ClientHello	Client sends supported cipher suites and PSK identity hint.
// 2	ServerHello	Server selects TLS_PSK_WITH_AES_128_CCM cipher.
// 3	ServerHelloDone	Server signals completion of Hello phase.
// 4	ClientKeyExchange	Client sends PSK identity.
// 5	ChangeCipherSpec (Client)	Client switches to encrypted mode.
// 6	Finished (Client)	Client verifies handshake.
// 7	ChangeCipherSpec (Server)	Server switches to encrypted mode.
// 8	Finished (Server)	Server verifies handshake.
// ✅	Secure Session Established	Encrypted communication begins!
// Let me know if you need a deeper dive into any part of the handshake! 🚀🔐
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_tls/ch09/handshake/change_cipher_spec.dart';
import 'package:dart_tls/ch09/handshake/handshake.dart';

import '../crypto.dart';
import '../dtls_message.dart';
import '../dtls_state.dart';
import '../enums.dart';
import '../handshake/certificate.dart';
import '../handshake/certificate_verify.dart';
import '../handshake/client_hello.dart';
import '../handshake/client_key_exchange.dart';
import '../handshake/extension.dart';
import '../handshake/finished.dart';
import '../handshake/handshake_context.dart';
import '../handshake/handshake_header.dart';
import '../handshake/hello_verify_request.dart';
import '../handshake/server_hello.dart';
import '../handshake/server_hello_done.dart';
import '../handshake/tls_random.dart';
import '../key_exchange_algorithm.dart';
import '../record_layer_header.dart';

HandshakeContext context = HandshakeContext();

class HandshakeManager {
  Uint8List serverCertificate = Uint8List(0);

  RawDatagramSocket socket;
  late int port;

  HandshakeManager(this.socket);

  Uint8List concatHandshakeMessageTo(
      Uint8List result,
      String resultTypes,
      Map<HandshakeType, Uint8List> messagesMap,
      String mapType,
      HandshakeType handshakeType)
// ([]byte, []string, bool)
  {
    final item = messagesMap[handshakeType];
    // if !ok {
    // 	return result, resultTypes, false
    // }
    result = Uint8List.fromList([...result, ...item!]);
    // resultTypes = append(resultTypes, fmt.Sprintf("%s (%s)", handshakeType, mapType))
    return result;
    //  resultTypes, true
  }

  Uint8List concatHandshakeMessages(HandshakeContext context,
      bool includeReceivedCertificateVerify, bool includeReceivedFinished)
//  ([]byte, []string, bool)
  {
    var result = Uint8List(0);
    String resultTypes = "";
    // var ok bool
    result = concatHandshakeMessageTo(result, resultTypes,
        context.HandshakeMessagesReceived, "recv", HandshakeType.client_hello);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(result, resultTypes,
        context.HandshakeMessagesSent, "sent", HandshakeType.server_hello);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(result, resultTypes,
        context.HandshakeMessagesSent, "sent", HandshakeType.certificate);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(
        result,
        resultTypes,
        context.HandshakeMessagesSent,
        "sent",
        HandshakeType.server_key_exchange);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(
        result,
        resultTypes,
        context.HandshakeMessagesSent,
        "sent",
        HandshakeType.certificate_request);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(result, resultTypes,
        context.HandshakeMessagesSent, "sent", HandshakeType.server_hello_done);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(result, resultTypes,
        context.HandshakeMessagesReceived, "recv", HandshakeType.certificate);
    // if !ok {
    // 	return nil, nil, false
    // }
    result = concatHandshakeMessageTo(
        result,
        resultTypes,
        context.HandshakeMessagesReceived,
        "recv",
        HandshakeType.client_key_exchange);
    // if !ok {
    // 	return nil, nil, false
    // }
    if (includeReceivedCertificateVerify) {
      result = concatHandshakeMessageTo(
          result,
          resultTypes,
          context.HandshakeMessagesReceived,
          "recv",
          HandshakeType.certificate_verify);
      // if !ok {
      // 	return nil, nil, false
      // }
    }
    if (includeReceivedFinished) {
      result = concatHandshakeMessageTo(result, resultTypes,
          context.HandshakeMessagesReceived, "recv", HandshakeType.finished);
      // if !ok {
      // 	return nil, nil, false
      // }
    }

    return result;
    // resultTypes, true
  }

  void processDtlsMessage(Uint8List data) {
    final dtlsMsg =
        DecodeDtlsMessageResult.decode(context, data, 0, data.length);

    // print("dtls message: $dtlsMsg");
    ProcessIncomingMessage(context, dtlsMsg);
  }

  bool? ProcessIncomingMessage(
      HandshakeContext context, DecodeDtlsMessageResult incomingMessage) {
    final (message, _, _) = incomingMessage.message;

    // print("Message runtime type: ${message.runtimeType}");
    switch (message.runtimeType) {
      case ClientHello:
        message as ClientHello;

        context.session_id = Uint8List.fromList(message.session_id);
        context.compression_methods = message.compression_methods;
        context.extensions = message.extensions;

        context.flight = Flight.Flight0;

        switch (context.flight) {
          case Flight.Flight0:
            context.dTLSState = DTLSState.DTLSStateConnecting;
            context.protocolVersion = message.client_version;
            context.cookie = generateDtlsCookie();
            // logging.Descf(logging.ProtoDTLS, "DTLS Cookie was generated and set to <u>0x%x</u> in handshake context (<u>%d bytes</u>).", context.Cookie, len(context.Cookie))

            context.flight = Flight.Flight2;
            // logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
            // logging.LineSpacer(2)
            // final helloVerifyRequestResponse =
            //     createDtlsHelloVerifyRequest(context);
            // sendMessage(context, helloVerifyRequestResponse);
            //return null;
            //case Flight.Flight2:
            // if (message.cookie.length == 0) {
            //   context.flight = Flight.Flight0;
            // logging.Errorf(logging.ProtoDTLS, "Expected not empty Client Hello Cookie but <nil> found!")
            // logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
            // logging.LineSpacer(2)
            //   return null;
            // }
            // if (!bytes.Equal(context.cookie, message.cookie)) {
            // 	throw ("client hello cookie is invalid");
            // }
            final negotiatedCipherSuite =
                negotiateOnCipherSuiteIDs(message.cipher_suites);
            // if (err != nil {
            // 	return m.setStateFailed(context, err)
            // }
            context.cipherSuite = negotiatedCipherSuite.value;
            // //logging.Descf(//logging.ProtoDTLS, "Negotiation on cipher suites: Client sent a list of cipher suites, server selected one of them (mutually supported), and assigned in handshake context: %s", negotiatedCipherSuite)
            // Convert map entries to a list
            final extensionList = message.extensions.entries.toList();

            for (var extensionItem in extensionList) {
              // print("Extension runtime type: ${extensionItem.runtimeType}");
              // switch (extensionItem) {
              //   case ExtensionType.ExtensionTypeSupportedEllipticCurves:
              //     final negotiatedCurve = negotiateOnCurves(extensionItem);
              //     // if err != nil {
              //     // 	return m.setStateFailed(context, err)
              //     // }
              //     context.curve = negotiatedCurve;
              //   //logging.Descf(//logging.ProtoDTLS, "Negotiation on curves: Client sent a list of curves, server selected one of them (mutually supported), and assigned in handshake context: <u>%s</u>", negotiatedCurve)
              //   case ExtensionType.ExtensionTypeUseSRTP:
              //     final negotiatedProtectionProfile =
              //         negotiateOnSRTPProtectionProfiles(
              //             extensionItem.ProtectionProfiles);
              //     // if err != nil {
              //     // 	return m.setStateFailed(context, err)
              //     // }
              //     context.srtpProtectionProfile = negotiatedProtectionProfile;
              //   //logging.Descf(//logging.ProtoDTLS, "Negotiation on SRTP protection profiles: Client sent a list of SRTP protection profiles, server selected one of them (mutually supported), and assigned in handshake context: <u>%s</u>", negotiatedProtectionProfile)
              //   case ExtensionType.ExtensionTypeUseExtendedMasterSecret:
              //     context.UseExtendedMasterSecret = true;
              //   //logging.Descf(//logging.ProtoDTLS, "Client sent UseExtendedMasterSecret extension, client wants to use ExtendedMasterSecret. We will generate the master secret via extended way further.")
              // }
            }

            context.clientRandom = message.random;
            //logging.Descf(//logging.ProtoDTLS, "Client sent Client Random, it set to <u>0x%x</u> in handshake context.", message.Random.Encode())
            context.serverRandom = TlsRandom.defaultInstance();
            // context.serverRandom.generate();
            //logging.Descf(//logging.ProtoDTLS, "We generated Server Random, set to <u>0x%x</u> in handshake context.", context.ServerRandom.Encode())

            //var keys = generateX25519Keys();
            // if err != nil {
            // 	return m.setStateFailed(context, err)
            // }

            //context.serverPublicKey = keys.publicKey;
            //context.serverPrivateKey = keys.privateKey;
            //logging.Descf(//logging.ProtoDTLS, "We generated Server Public and Private Key pair via <u>%s</u>, set in handshake context. Public Key: <u>0x%x</u>", context.Curve, context.ServerPublicKey)

            // final clientRandomBytes = context.clientRandom.marshal();
            // final serverRandomBytes = context.serverRandom.marshal();

            //logging.Descf(//logging.ProtoDTLS, "Generating ServerKeySignature. It will be sent to client via ServerKeyExchange DTLS message further.")
            // context.serverKeySignature = generateKeySignature(
            //     clientRandomBytes,
            //     serverRandomBytes,
            //     context.serverPublicKey,
            //     // context.curve, //x25519
            //     context.serverPrivateKey);
            // if err != nil {
            // 	return m.setStateFailed(context, err)
            // }
            //logging.Descf(//logging.ProtoDTLS, "ServerKeySignature was generated and set in handshake context (<u>%d bytes</u>).", len(context.ServerKeySignature))

            context.flight = Flight.Flight4;
            //logging.Descf(//logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
            //logging.LineSpacer(2)
            final serverHelloResponse = createServerHello(context);
            sendMessage(context, serverHelloResponse);
            // final certificateResponse = createDtlsCertificate();
            // sendMessage(context, certificateResponse);
            //  final serverKeyExchangeResponse =
            //      createDtlsServerKeyExchange(context);
            //   sendMessage(context, serverKeyExchangeResponse);
            //   final certificateRequestResponse =
            //       createDtlsCertificateRequest(context);
            //   sendMessage(context, certificateRequestResponse);
            final serverHelloDoneResponse = createDtlsServerHelloDone(context);
            sendMessage(context, serverHelloDoneResponse);

          default:
            {
              print("Unhandle flight: ${context.flight}");
            }
        }
      case Certificate:
        context.clientCertificates = message.certificates;
        //logging.Descf(//logging.ProtoDTLS, "Generating certificate fingerprint hash from incoming Client Certificate...")
        final certificateFingerprintHash =
            getCertificateFingerprintFromBytes(context.clientCertificates[0]);
        //logging.Descf(//logging.ProtoDTLS, "Checking fingerprint hash of client certificate incoming by this packet <u>%s</u> equals to expected fingerprint hash <u>%s</u> came from Signaling SDP", certificateFingerprintHash, context.ExpectedFingerprintHash)
        if (context.expectedFingerprintHash != certificateFingerprintHash) {
          throw ("incompatible fingerprint hashes from SDP and DTLS data");
        }
      case CertificateVerify:
      //logging.Descf(//logging.ProtoDTLS, "Checking incoming HashAlgorithm <u>%s</u> equals to negotiated before via hello messages <u>%s</u>", message.AlgoPair.HashAlgorithm, context.CipherSuite.HashAlgorithm)
      //logging.Descf(//logging.ProtoDTLS, "Checking incoming SignatureAlgorithm <u>%s</u> equals to negotiated before via hello messages <u>%s</u>", message.AlgoPair.SignatureAlgorithm, context.CipherSuite.SignatureAlgorithm)
      //logging.LineSpacer(2)
      // if (!(context.cipherSuite.HashAlgorithm == message.algoPair.hashAlgorithm &&
      // 	HashAlgorithm(context.cipherSuite.signatureAlgorithm) == HashAlgorithm(message.algoPair.signatureAlgorithm)) {
      // 	throw("incompatible signature scheme");
      // }
      // final (handshakeMessages, handshakeMessageTypes, ok) =
      //     concatHandshakeMessages(context, false, false);
      // if (!ok) {
      //   throw ("error while concatenating handshake messages");
      // }
      //logging.Descf(//logging.ProtoDTLS,
      // common.JoinSlice("\n", false,
      // 	common.ProcessIndent("Verifying client certificate...", "+", []string{
      // 		fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
      // 		fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
      // 		"Verifying the calculated hash, the incoming signature by CertificateVerify message and client certificate public key.",
      // 	})))
      // final err = verifyCertificate(
      //     handshakeMessages,
      //     context.cipherSuite.hashAlgorithm,
      //     message.signature,
      //     context.clientCertificates);
      // if err != nil {
      // 	return m.setStateFailed(context, err)
      // }
      case ClientKeyExchange:
        context.clientKeyExchangePublic = message.publicKey;

        // print("Client key exchange: ${message}");
        // if (!context.isCipherSuiteInitialized) {
        //   final err = initCipherSuite(context);
        //   // if err != nil {
        //   // 	return m.setStateFailed(context, err)
        //   // }
        // }

        final changeCipherSpecResponse = createDtlsChangeCipherSpec(context);
        sendMessage(context, changeCipherSpecResponse);
      case Finished:
        print("Finished: ${message}");
      //logging.Descf(//logging.ProtoDTLS, "Received first encrypted message and decrypted successfully: Finished (epoch was increased to <u>%d</u>)", context.ClientEpoch)
      //logging.LineSpacer(2)

      // final (handshakeMessages, handshakeMessageTypes, ok) =
      //     concatHandshakeMessages(context, true, true);
      // if (!ok) {
      // 	return setStateFailed(context, errors.New("error while concatenating handshake messages"))
      // }
      //logging.Descf(//logging.ProtoDTLS,
      // common.JoinSlice("\n", false,
      // 	common.ProcessIndent("Verifying Finished message...", "+", []string{
      // 		fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
      // 		fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>, using server master secret.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
      // 	})))
      // final (calculatedVerifyData, err) = verifyFinishedData(
      //     handshakeMessages,
      //     context.serverMasterSecret,
      //     context.cipherSuite.hashAlgorithm);
      // if err != nil {
      // 	return m.setStateFailed(context, err)
      // }
      //logging.Descf(//logging.ProtoDTLS, "Calculated Finish Verify Data: <u>0x%x</u> (<u>%d bytes</u>). This data will be sent via Finished message further.", calculatedVerifyData, len(calculatedVerifyData))
      // context.flight = Flight.Flight6;
      // //logging.Descf(//logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
      // //logging.LineSpacer(2)
      // final changeCipherSpecResponse = createDtlsChangeCipherSpec(context);
      // sendMessage(context, changeCipherSpecResponse);
      // context.increaseServerEpoch();

      // final finishedResponse =
      //     createDtlsFinished(context, calculatedVerifyData);
      // sendMessage(context, finishedResponse);
      // //logging.Descf(//logging.ProtoDTLS, "Sent first encrypted message successfully: Finished (epoch was increased to <u>%d</u>)", context.ServerEpoch)
      // //logging.LineSpacer(2)

      // //logging.Infof(//logging.ProtoDTLS, "Handshake Succeeded with <u>%v:%v</u>.\n", context.Addr.IP, context.Addr.Port)
      // context.dTLSState = DTLSState.DTLSStateConnected;
      default:
        {
          print("Unhandled runtime type: ${message.runtimeType}");
        }
    }
  }

  createDtlsServerKeyExchange(HandshakeContext context) {}

  createDtlsCertificate() {}

  ServerHello createServerHello(HandshakeContext context) {
    // final ch = context.HandshakeMessagesReceived[HandshakeType.client_hello]
    //     as ClientHello;

    return ServerHello(
        context.protocolVersion,
        context.serverRandom,
        context.session_id.length,
        context.session_id,
        CipherSuiteId.Tls_Psk_With_Aes_128_Ccm_8.value,
        context.compression_methods[0],
        context.extensions);
  }

  CipherSuiteId negotiateOnCipherSuiteIDs(List<CipherSuiteId> cipherSuiteIDs) {
    return CipherSuiteId.Tls_Psk_With_Aes_128_Ccm;
  }

  createDtlsCertificateRequest(HandshakeContext context) {}

  ServerHelloDone createDtlsServerHelloDone(HandshakeContext context) {
    return ServerHelloDone();
  }

  verifyCertificate(Object? handshakeMessages, hashAlgorithm, signature,
      clientCertificates) {}

  getCertificateFingerprintFromBytes(clientCertificat) {}

  initCipherSuite(HandshakeContext context) {}

  verifyFinishedData(
      Object? handshakeMessages, serverMasterSecret, hashAlgorithm) {}

  ChangeCipherSpec createDtlsChangeCipherSpec(HandshakeContext context) {
    return ChangeCipherSpec();
  }

  // extension on HandshakeContext {
  //  void increaseServerEpoch() {}
  // }

  void sendMessage(HandshakeContext context, dynamic message) {
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
    socket.send(messageToSend, socket.address, port);
    context.increaseServerSequence();
  }

  createDtlsFinished(HandshakeContext context, calculatedVerifyData) {}

  generateCurveKeypair(Uint8List curve) {}

  HelloVerifyRequest createDtlsHelloVerifyRequest(HandshakeContext context) {
    HelloVerifyRequest hvr = HelloVerifyRequest(
        version: context.protocolVersion, cookie: generateDtlsCookie());
    return hvr;
  }

  Uint8List generateDtlsCookie() {
    final cookie = Uint8List(20);
    final random = Random.secure();
    for (int i = 0; i < cookie.length; i++) {
      cookie[i] = random.nextInt(256);
    }
    return cookie;
  }

  negotiateOnCurves(curves) {}
  negotiateOnSRTPProtectionProfiles(protectionProfiles) {}
}
