// Diffie-Hellman algorithm:
// The Diffie-Hellman algorithm is being used to establish a shared secret that can be used for secret communications while exchanging data over a public network using the elliptic curve to generate points and get the secret key using the parameters.
//
// For the sake of simplicity and practical implementation of the algorithm, we will consider only 4 variables, one prime P and G (a primitive root of P) and two private values a and b.
// P and G are both publicly available numbers. Users (say Alice and Bob) pick private values a and b and they generate a key and exchange it publicly. The opposite person receives the key and that generates a secret key, after which they have the same secret key to encrypt.
//
// Step-by-Step explanation is as follows:
//
// Alice		Bob
// Public Keys available = P, G	Public Keys available = P, G
// Private Key Selected = a		Private Key Selected = b
// Key generated = x = G^a mod P	Key generated = y = G^b mod P
// Exchange of generated keys takes place
// Key received = y		Key received = x
// Generated Secret Key = ka = y^a mod P	Generated Secret Key = kb = x^b mod P
// Algebraically, it can be shown that ka = kb
// Users now have a symmetric secret key to encrypt

// Power function to return value of a ^ b mod P
BigInt power(BigInt a, BigInt b, BigInt P) {
  return a.modPow(b, P);
}

void main() {
  BigInt P = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);
  // ignore: non_constant_identifier_names
  BigInt Gx = BigInt.parse(
      '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
      radix: 16);
  // ignore: non_constant_identifier_names
  BigInt Gy = BigInt.parse(
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162cb1baaa2c7e5d74b902d096fd5b91d1',
      radix: 16);
  print(
      "The generator point G (x, y) : (${Gx.toRadixString(16)}, ${Gy.toRadixString(16)})");

  // Alice's private key
  BigInt a =
      BigInt.parse('c8f3a74eb3d2c4b7b6e1ef6e34cf74a1c1eaf3eb', radix: 16);
  print("The private key a for Alice : $a");
  BigInt ax = power(Gx, a, P);
  BigInt ay = power(Gy, a, P);
  print(
      "Alice's public key (uncompressed): 04${ax.toRadixString(16).padLeft(64, '0')}${ay.toRadixString(16).padLeft(64, '0')}");

  // Bob's private key
  BigInt b =
      BigInt.parse('a4d1c5a1f3f7ecf9b5a3d2c9e74a1c2b3f6e1d8a', radix: 16);
  print("The private key b for Bob : $b");
  BigInt bx = power(Gx, b, P);
  BigInt by = power(Gy, b, P);
  print(
      "Bob's public key (uncompressed): 04${bx.toRadixString(16).padLeft(64, '0')}${by.toRadixString(16).padLeft(64, '0')}");

  // Compute shared secret key
  BigInt aliceShared = power(bx, a, P);
  BigInt bobShared = power(ax, b, P);
  print("Secret key for Alice: ${aliceShared.toRadixString(16)}");
  print("Secret key for Bob:   ${bobShared.toRadixString(16)}");
}
