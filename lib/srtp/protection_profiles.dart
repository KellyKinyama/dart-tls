import 'dart:typed_data';

enum ProtectionProfile {
  aeadAes128Gcm(0x0007, 16, 12, 16);

  final int value;
  final int keyLength;
  final int saltLength;
  final int aeadAuthTagLength;

  const ProtectionProfile(
      this.value, this.keyLength, this.saltLength, this.aeadAuthTagLength);

  @override
  String toString() {
    switch (this) {
      case ProtectionProfile.aeadAes128Gcm:
        return 'SRTP_AEAD_AES_128_GCM (0x${value.toRadixString(16).padLeft(4, '0')})';
      default:
        return 'Unknown SRTP Protection Profile';
    }
  }
}

class EncryptionKeys {
  final Uint8List serverMasterKey;
  final Uint8List serverMasterSalt;
  final Uint8List clientMasterKey;
  final Uint8List clientMasterSalt;

  EncryptionKeys({
    required this.serverMasterKey,
    required this.serverMasterSalt,
    required this.clientMasterKey,
    required this.clientMasterSalt,
  });
}

Future<GCM?> initGCM(Uint8List masterKey, Uint8List masterSalt) async {
  try {
    return await GCM.newInstance(masterKey, masterSalt);
  } catch (e) {
    return null;
  }
}

class GCM {
  final Uint8List masterKey;
  final Uint8List masterSalt;

  GCM._(this.masterKey, this.masterSalt);

  static Future<GCM> newInstance(
      Uint8List masterKey, Uint8List masterSalt) async {
    return GCM._(masterKey, masterSalt);
  }
}
