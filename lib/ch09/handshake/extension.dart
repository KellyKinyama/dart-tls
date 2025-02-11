import 'dart:typed_data';
import 'dart:convert';

// Placeholder classes and enums for the extension types (for example purposes)

enum ExtensionType {
  ExtensionTypeServerName(0),
  ExtensionTypeSupportedEllipticCurves(10),
  ExtensionTypeSupportedPointFormats(11),
  ExtensionTypeSupportedSignatureAlgorithms(13),
  ExtensionTypeUseSRTP(14),
  ExtensionTypeALPN(16),
  ExtensionTypeUseExtendedMasterSecret(23),
  ExtensionTypeRenegotiationInfo(65),

  ExtensionTypeUnknown(65535); //Not a valid value

  const ExtensionType(this.value);
  final int value;

  static ExtensionType fromInt(int value) {
    switch (value) {
      case 0:
        return ExtensionTypeServerName;
      case 10:
        return ExtensionTypeSupportedEllipticCurves;
      case 11:
        return ExtensionTypeSupportedPointFormats;
      case 13:
        return ExtensionTypeSupportedSignatureAlgorithms;
      case 14:
        return ExtensionTypeUseSRTP;
      case 16:
        return ExtensionTypeALPN;
      case 23:
        return ExtensionTypeUseExtendedMasterSecret;
      case 65:
        return ExtensionTypeRenegotiationInfo;
      default:
        return ExtensionTypeUnknown;
    }
  }
}

abstract class Extension {
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);

  ExtensionType getExtensionType();
}

class ExtUseExtendedMasterSecret extends Extension {
  @override
  String toString() {
    return "[UseExtendedMasterSecret]";
  }

  @override
  ExtensionType getExtensionType() {
    return ExtensionType.ExtensionTypeUseExtendedMasterSecret;
  }

  List<int> encode() {
    return [];
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    // No implementation needed for this example
  }
}

class ExtRenegotiationInfo extends Extension {
  @override
  String toString() {
    return "[RenegotiationInfo]";
  }

  ExtensionType getExtensionType() {
    return ExtensionType.ExtensionTypeRenegotiationInfo;
  }

  List<int> encode() {
    return [0];
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    // No implementation needed for this example
  }
}

class ExtUseSRTP extends Extension {
  List<int> protectionProfiles = [];
  List<int> mki = [];

  @override
  String toString() {
    return "[UseSRTP] Protection Profiles: $protectionProfiles\nMKI: $mki";
  }

  ExtensionType getExtensionType() {
    return ExtensionType.ExtensionTypeUseSRTP;
  }

  List<int> encode() {
    List<int> result = [];
    result.add((protectionProfiles.length * 2) >> 8); // Length in MSB
    result.add((protectionProfiles.length * 2) & 0xFF); // Length in LSB
    protectionProfiles.forEach((profile) {
      result.add((profile >> 8) & 0xFF); // Profile MSB
      result.add(profile & 0xFF); // Profile LSB
    });
    result.add(mki.length);
    result.addAll(mki);
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    int protectionProfilesLength = (buf[offset] << 8) | buf[offset + 1];
    int protectionProfilesCount = protectionProfilesLength ~/ 2;
    offset += 2;
    protectionProfiles = List.generate(protectionProfilesCount, (i) {
      int profile = (buf[offset] << 8) | buf[offset + 1];
      offset += 2;
      return profile;
    });

    int mkiLength = buf[offset];
    offset++;
    mki = buf.sublist(offset, offset + mkiLength);
    offset += mkiLength;
  }
}

class ExtSupportedPointFormats extends Extension {
  List<int> pointFormats = [];

  @override
  String toString() {
    return "[SupportedPointFormats] Point Formats: $pointFormats";
  }

  @override
  ExtensionType getExtensionType() {
    return ExtensionType.ExtensionTypeSupportedPointFormats;
  }

  List<int> encode() {
    List<int> result = [];
    result.add(pointFormats.length);
    result.addAll(pointFormats);
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    int pointFormatsCount = buf[offset];
    offset++;
    pointFormats = List.generate(pointFormatsCount, (i) {
      int format = buf[offset];
      offset++;
      return format;
    });
  }
}

class ExtSupportedEllipticCurves extends Extension {
  List<int> curves = [];

  @override
  String toString() {
    return "[SupportedEllipticCurves] Curves: $curves";
  }

  @override
  ExtensionType getExtensionType() {
    return ExtensionType.ExtensionTypeSupportedEllipticCurves;
  }

  List<int> encode() {
    List<int> result = [];
    result.add((curves.length * 2) >> 8); // Length in MSB
    result.add((curves.length * 2) & 0xFF); // Length in LSB
    curves.forEach((curve) {
      result.add((curve >> 8) & 0xFF); // Curve MSB
      result.add(curve & 0xFF); // Curve LSB
    });
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    int curvesLength = (buf[offset] << 8) | buf[offset + 1];
    int curvesCount = curvesLength ~/ 2;
    offset += 2;
    curves = List.generate(curvesCount, (i) {
      int curve = (buf[offset] << 8) | buf[offset + 1];
      offset += 2;
      return curve;
    });

    print("Curves: $curves");
  }
}

class ExtUnknown extends Extension {
  final int type;
  final int dataLength;

  ExtUnknown({required this.type, required this.dataLength});

  @override
  String toString() {
    return "[Unknown Extension Type] Ext Type: <u>$type</u>, Data: <u>$dataLength bytes</u>";
  }

  ExtensionType getExtensionType() {
    return ExtensionType.ExtensionTypeUnknown;
  }

  List<int> encode() {
    throw UnsupportedError("ExtUnknown cannot be encoded, it's readonly");
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    // No implementation needed for this example
  }
}

// Decoding method
Map<ExtensionType, Extension> decodeExtensionMap(
    Uint8List buf, int offset, int arrayLen) {
  Map<ExtensionType, Extension> result = {};
  int length =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  offset += 2;

  int offsetBackup = offset;
  while (offset < offsetBackup + length) {
    ExtensionType extensionType = ExtensionType.fromInt(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;

    int extensionLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;

    Extension? extension;
    switch (extensionType) {
      case ExtensionType.ExtensionTypeUseExtendedMasterSecret:
        extension = ExtUseExtendedMasterSecret();
        break;
      case ExtensionType.ExtensionTypeRenegotiationInfo:
        extension = ExtRenegotiationInfo();
        break;
      case ExtensionType.ExtensionTypeUseSRTP:
        extension = ExtUseSRTP();
        break;
      case ExtensionType.ExtensionTypeSupportedPointFormats:
        extension = ExtSupportedPointFormats();
        break;
      case ExtensionType.ExtensionTypeSupportedEllipticCurves:
        extension = ExtSupportedEllipticCurves();
        break;
      default:
        extension =
            ExtUnknown(type: extensionType.index, dataLength: extensionLength);
    }

    extension.decode(extensionLength, buf, offset, arrayLen);
    result[extension.getExtensionType()] = extension;

    offset += extensionLength;
  }
  return result;
}
