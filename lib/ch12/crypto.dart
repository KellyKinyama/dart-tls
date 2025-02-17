import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';

class TLS {
  static const int MASTER_SECRET_LENGTH = 48;

  // The PRF function computes the master secret using the pre_master_secret, label, and random values.
  static Uint8List prf(
      Uint8List preMasterSecret, String label, Uint8List randomData) {
    // Simulating a simplified PRF function (this would be much more complex in reality).
    var concatenated = Uint8List.fromList(
        [...preMasterSecret, ...utf8.encode(label), ...randomData]);
    var hash = _sha256(concatenated);
    return hash.sublist(
        0, MASTER_SECRET_LENGTH); // Ensure the master secret is 48 bytes.
  }

  // Simplified SHA-256 function for demonstration purposes.
  static Uint8List _sha256(Uint8List data) {
    var digest = SHA256().convert(data);
    return digest.bytes;
  }

  // RSA: Simulates the generation of the pre-master secret and encrypts it with the server's public key.
  static Uint8List rsaEncrypt(
      Uint8List preMasterSecret, RSAKey serverPublicKey) {
    // In a real scenario, you would use RSA encryption with the server's public key here.
    // For this simulation, we just return the preMasterSecret as the encrypted value.
    return preMasterSecret; // Placeholder.
  }

  // Diffie-Hellman: Computes the pre-master secret using the shared secret 'Z'.
  static Uint8List diffieHellmanToMasterSecret(
      Uint8List sharedSecret, Uint8List clientRandom, Uint8List serverRandom) {
    // Remove leading zero bits if necessary (in a real implementation, this would involve complex math).
    var cleanedSharedSecret = _stripLeadingZeroBits(sharedSecret);

    // Compute the master secret using PRF (simplified).
    return prf(
        cleanedSharedSecret, "master secret", clientRandom + serverRandom);
  }

  static Uint8List _stripLeadingZeroBits(Uint8List sharedSecret) {
    int index = 0;
    while (index < sharedSecret.length && sharedSecret[index] == 0) {
      index++;
    }
    return sharedSecret.sublist(index);
  }
}

// Simulating RSA key structure (in a real scenario, RSA keys would be more complex).
class RSAKey {
  final Uint8List publicKey;
  RSAKey(this.publicKey);
}

// Main function for testing
void main() {
  // Simulate pre-master secret generation and encryption (for RSA).
  Uint8List preMasterSecret = Uint8List(48); // 48-byte pre-master secret.
  var rng = Random();
  rng.nextBytes(preMasterSecret); // Fill with random data.

  // Simulated server public key (this would be used for real RSA encryption).
  RSAKey serverPublicKey = RSAKey(Uint8List(128)); // Placeholder public key.

  // Encrypt the pre-master secret using RSA (simulation).
  var encryptedPreMasterSecret =
      TLS.rsaEncrypt(preMasterSecret, serverPublicKey);

  // Simulate Diffie-Hellman computation (for shared secret 'Z').
  Uint8List sharedSecret =
      Uint8List(64); // 64-byte shared secret (placeholder).
  rng.nextBytes(sharedSecret);

  // Client and Server Random values (simulated).
  Uint8List clientRandom = Uint8List(32);
  Uint8List serverRandom = Uint8List(32);
  rng.nextBytes(clientRandom);
  rng.nextBytes(serverRandom);

  // Compute the master secret using Diffie-Hellman.
  var masterSecret =
      TLS.diffieHellmanToMasterSecret(sharedSecret, clientRandom, serverRandom);

  // Output the results.
  print('Encrypted PreMasterSecret: ${encryptedPreMasterSecret}');
  print('Master Secret (Diffie-Hellman): $masterSecret');
}
