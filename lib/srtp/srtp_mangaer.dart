import 'dart:typed_data';
import 'package:dart_tls/srtp/protection_profiles.dart';

import 'srtp_context.dart';
import 'gcm.dart';
import 'protection_profile.dart';
import 'encryption_keys.dart';

class SRTPManager {
  SRTPManager();

  SRTPContext newContext(ProtectionProfile protectionProfile) {
    return SRTPContext(protectionProfile, null);
  }

  EncryptionKeys extractEncryptionKeys(
      ProtectionProfile protectionProfile, Uint8List keyingMaterial) {
    final keyLength = protectionProfile.keyLength();
    final saltLength = protectionProfile.saltLength();

    int offset = 0;
    final clientMasterKey =
        keyingMaterial.sublist(offset, offset + keyLength);
    offset += keyLength;
    final serverMasterKey =
        keyingMaterial.sublist(offset, offset + keyLength);
    offset += keyLength;
    final clientMasterSalt =
        keyingMaterial.sublist(offset, offset + saltLength);
    offset += saltLength;
    final serverMasterSalt =
        keyingMaterial.sublist(offset, offset + saltLength);

    return EncryptionKeys(
      clientMasterKey: clientMasterKey,
      clientMasterSalt: clientMasterSalt,
      serverMasterKey: serverMasterKey,
      serverMasterSalt: serverMasterSalt,
    );
  }

  void initCipherSuite(SRTPContext context, Uint8List keyingMaterial) {
    final keys = extractEncryptionKeys(context.protectionProfile, keyingMaterial);
    context.gcm = GCM(keys.clientMasterKey, keys.clientMasterSalt);
  }
}
