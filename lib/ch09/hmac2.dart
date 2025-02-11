import 'dart:typed_data';
import 'package:crypto/crypto.dart';

List<int> hmacSha256(Uint8List key, Uint8List data) {
  final hmac = Hmac(sha256, key);
  return hmac.convert(data).bytes;
}
