import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/equality.dart';

import 'cert_utils.dart';

/// Decodes a PEM-encoded certificate into DER format.
Uint8List pemDecode(String pem) {
  // Check if the input starts with a valid PEM header
  if (!pem.startsWith("-----BEGIN")) {
    throw FormatException(
        "This does not appear to be a PEM-encoded certificate file.");
  }

  // Extract the Base64-encoded part by removing PEM headers/footers
  final pemLines = pem.split('\n');
  final base64Lines = pemLines
      .where((line) =>
          !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
      .join('');

  // Decode from Base64 to raw DER bytes
  return base64Decode(base64Lines);
}

void main() {
  // Example PEM certificate (truncated for brevity)
  String pemCertificate = '''
-----BEGIN CERTIFICATE-----
MIICZDCCAgqgAwIBAgIUSYr0ahwK6h8/kk2u+99h+KOFwWowCgYIKoZIzj0EAwIw
gYgxCzAJBgNVBAYTAnptMQ8wDQYDVQQIDAZ6YW1iaWExDzANBgNVBAcMBmx1c2Fr
YTEOMAwGA1UECgwFemVzY28xDDAKBgNVBAsMA2lzZDEUMBIGA1UEAwwLc2VsZi1z
aWduZWQxIzAhBgkqhkiG9w0BCQEWFGtraW55YW1hQHplc2NvLmNvLnptMB4XDTI1
MDEyODExNTEzNVoXDTI2MDEyODExNTEzNVowgYgxCzAJBgNVBAYTAnptMQ8wDQYD
VQQIDAZ6YW1iaWExDzANBgNVBAcMBmx1c2FrYTEOMAwGA1UECgwFemVzY28xDDAK
BgNVBAsMA2lzZDEUMBIGA1UEAwwLc2VsZi1zaWduZWQxIzAhBgkqhkiG9w0BCQEW
FGtraW55YW1hQHplc2NvLmNvLnptMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEDxtD
onMyuCmQG+22oZ9cG+qCvubBxInwBuvqt+T8t31TRUeFWmwqDUPvgfyXdOKShnw1
Q5VTgdZ9yJU9j3Yxv6NTMFEwHQYDVR0OBBYEFBhrKLlCWl9u7DtnspbwcYLNtz9D
MB8GA1UdIwQYMBaAFBhrKLlCWl9u7DtnspbwcYLNtz9DMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIgPkmNWnoMeD5vr+83yfkFS+Tv4shGVoyjk3m5
NJ3mDc8CIQDK8h0fzGGuoLOrHXb4fnjB9N3gb5srdLC4bgQeLBOLcw==
-----END CERTIFICATE-----
''';

  // Convert to DER format
  Uint8List derBytes = pemDecode(pemCertificate);
  List<int> certificateBytes = pemToBytes(pemCertificate);

  // print("DER (Bytes): $derBytes");
  // print("DER (Bytes): $certificateBytes");

  print(
      "Bytes are equal is: ${ListEquality().equals(derBytes, certificateBytes)}");

  // Print the result as a hex string
  // print(
  //     "DER (Hex): ${derBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}");
}
