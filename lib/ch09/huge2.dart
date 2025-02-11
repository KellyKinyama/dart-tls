class Huge {
  late int sign;
  late int size;
  BigInt rep;

  Huge(this.rep) {
    sign = rep.sign;
    size = rep.bitLength + 1;
  }

  factory Huge.fromList(List<int> input) {
    BigInt out = BigInt.from(0);

    for (int val in input) {
      out = out + BigInt.from(val);
    }

    return Huge(out);
  }

  factory Huge.from(int input) {
    BigInt out = BigInt.from(input);

    return Huge(out);
  }
}
