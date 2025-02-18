// Diffie-Hellman algorithm:
// The Diffie-Hellman algorithm is being used to establish a shared secret that
//can be used for secret communications while exchanging data over a public
//network using the elliptic curve to generate points and get the secret key
//using the parameters.
//
// For the sake of simplicity and practical implementation of the algorithm, we
// will consider only 4 variables, one prime P and G (a primitive root of P) and
// two private values a and b.
// P and G are both publicly available numbers. Users (say Alice and Bob) pick
//private values a and b and they generate a key and exchange it publicly.
//The opposite person receives the key and that generates a secret key,
//after which they have the same secret key to encrypt.
//
// Step-by-Step explanation is as follows:
//
// Alice			Bob
// Public Keys available = P, G	Public Keys available = P, G
// Private Key Selected = a		Private Key Selected = b
// Key generated = x = G^a mod P	Key generated = y = G^b mod P
// Exchange of generated keys takes place
// Key received = y			Key received = x
// Generated Secret Key = ka = y^a mod P	Generated Secret Key = kb = x^b mod P
// Algebraically, it can be shown that ka = kb
// Users now have a symmetric secret key to encrypt

// Power function to return value of a ^ b mod P

// Power function to return value of a ^ b mod P
BigInt power(BigInt a, BigInt b, BigInt P) {
  return a.modPow(b, P);
}

void main() {
  BigInt P = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16); // prime256
  print("The value of P : $P");

  BigInt G = BigInt.from(2); // A primitive root for P, G is taken
  print("The value of G : $G");

  // Alice will choose the private key a
  BigInt a = BigInt.parse('c8f3a74eb3d2c4b7b6e1ef6e34cf74a1c1eaf3eb',
      radix: 16); // private key
  print("The private key a for Alice : $a");

  BigInt x = power(G, a, P); //Alice gets the generated public key X.
  print("Generated key x (Alice) in radix 16: ${x.toRadixString(16)}");
  print("Length of x in radix 16: ${x.toRadixString(16).length}");
  print("Length of x in bytes: ${(x.bitLength + 7) ~/ 8}");

  // Bob will choose the private key b
  BigInt b = BigInt.parse('a4d1c5a1f3f7ecf9b5a3d2c9e74a1c2b3f6e1d8a',
      radix: 16); // private key
  print("The private key b for Bob : $b");

  BigInt y = power(G, b, P); // Bod gets the generated public key Y
  print("Generated key y (Bob) in radix 16: ${y.toRadixString(16)}");
  print("Length of y in radix 16: ${y.toRadixString(16).length}");
  print("Length of y in bytes: ${(y.bitLength + 7) ~/ 8}");

  // Generating the secret key after the exchange of keys
  BigInt ka = power(y, a, P); // Secret key for Alice
  BigInt kb = power(x, b, P); // Secret key for Bob
  print("Secret key for Alice is : $ka");
  print("Secret key for Bob is   : $kb");
}
