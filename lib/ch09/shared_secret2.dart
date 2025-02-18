// Power function to return value of a ^ b mod P
BigInt power(BigInt a, BigInt b, BigInt P) {
  if (b == BigInt.from(1)) {
    // return a % P;
    return a.modPow(BigInt.from(1), P);
  }
  // return (pow(a, b).toInt() % P);
  return a.modPow(b, P);
}

void main() {
  BigInt P = BigInt.from(23); // A prime number P is taken
  print("The value of P : $P");

  BigInt G = BigInt.from(9); // A primitive root for P, G is taken
  print("The value of G : $G");

  // Alice will choose the private key a
  BigInt a = BigInt.from(4); // a is the chosen private key
  print("The private key a for Alice : $a");

  BigInt x = power(G, a, P); // gets the generated key

  // Bob will choose the private key b
  BigInt b = BigInt.from(3); // b is the chosen private key
  print("The private key b for Bob : $b");

  BigInt y = power(G, b, P); // gets the generated key

  // Generating the secret key after the exchange of keys
  BigInt ka = power(y, a, P); // Secret key for Alice
  BigInt kb = power(x, b, P); // Secret key for Bob
  print("Secret key for Alice is : $ka");
  print("Secret key for Bob is : $kb");
}
