import 'dart:math';

// Power function to return value of a ^ b mod P
int power(int a, int b, int P) {
  if (b == 1) {
    return a % P;
  }
  return (pow(a, b).toInt() % P);
}

void main() {
  int P = 23; // A prime number P is taken
  print("The value of P : $P");

  int G = 9; // A primitive root for P, G is taken
  print("The value of G : $G");

  // Alice will choose the private key a
  int a = 4; // a is the chosen private key
  print("The private key a for Alice : $a");

  int x = power(G, a, P); // gets the generated key

  // Bob will choose the private key b
  int b = 3; // b is the chosen private key
  print("The private key b for Bob : $b");

  int y = power(G, b, P); // gets the generated key

  // Generating the secret key after the exchange of keys
  int ka = power(y, a, P); // Secret key for Alice
  int kb = power(x, b, P); // Secret key for Bob
  print("Secret key for Alice is : $ka");
  print("Secret key for Bob is : $kb");
}
