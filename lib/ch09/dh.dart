import "huge.dart";

class DhKey {
  Huge p;
  Huge g;
  Huge Y; // Ys for server or Yc for client

  DhKey(this.p, this.g, this.Y);
}


// There's no corresponding .c file for this header; Diffie-Hellman
// key exchange is accomplished entirely with huge.c's mod_pow.