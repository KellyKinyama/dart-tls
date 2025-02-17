import 'dart:typed_data';

class Huge {
  BigInt value;

  Huge(this.value);

  factory Huge.fromInt(int val) {
    return Huge(BigInt.from(val));
  }

  void copyFrom(Huge src) {
    value = src.value;
  }

  void setValue(int val) {
    value = BigInt.from(val);
  }

  int compareTo(Huge other) {
    return value.compareTo(other.value);
  }

  void add(Huge other) {
    value += other.value;
  }

  Huge operator +(Huge other) {
    return Huge(value + other.value);
  }

  Huge operator -(Huge other) {
    return Huge(value - other.value);
  }

  Huge operator *(Huge other) {
    return Huge(value * other.value);
  }

  Huge operator ~/(Huge other) {
    return Huge(value ~/ other.value);
  }

  void subtract(Huge other) {
    value -= other.value;
  }

  void multiply(Huge other) {
    value *= other.value;
  }

  void divide(Huge divisor, Huge quotient) {
    quotient.value = value ~/ divisor.value;
  }

  void load(Uint8List bytes) {
    value = BigInt.parse(
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        radix: 16);
  }

  Uint8List unload(int length) {
    String hex = value.toRadixString(16).padLeft(length * 2, '0');
    return Uint8List.fromList(List.generate(
        length, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16)));
  }

  void free() {
    value = BigInt.zero;
  }

  factory Huge.zero() => Huge(BigInt.zero);

  void modPow(Huge exp, Huge n, Huge result) {
    result.value = value.modPow(exp.value, n.value);
  }

  void inv(Huge a) {
    value = a.value.modInverse(value);
  }

  void contract() {
    value = value.toUnsigned(value.bitLength);
  }

  @override
  String toString() => value.toString();
}
