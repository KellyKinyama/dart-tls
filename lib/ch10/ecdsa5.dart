import 'dart:math';
import 'dart:typed_data';

class Curve {
  final BigInt n;
  final int bitSize;
  final ECPoint Function(List<int>) scalarBaseMul;
  final ECPoint Function(PublicKey, List<int>) scalarMul;
  final ECPoint Function(ECPoint, ECPoint) add;

  Curve({
    required this.n,
    required this.bitSize,
    required this.scalarBaseMul,
    required this.scalarMul,
    required this.add,
  });
}

class ECPoint {
  BigInt X;
  BigInt Y;

  ECPoint(this.X, this.Y);
}

class PrivateKey {
  final BigInt D;
  final Curve curve;

  PrivateKey(this.D, this.curve);
}

class PublicKey {
  final ECPoint Q;
  final Curve curve;

  PublicKey(this.Q, this.curve);
}

class Signature {
  BigInt R = BigInt.zero;
  BigInt S = BigInt.zero;

  Signature.fromRS(this.R, this.S);
}

BigInt bitsToInt(List<int> bytes, int bitLength) {
  return BigInt.parse(
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
}

Signature signature(PrivateKey priv, List<int> hash) {
  var curve = priv.curve;

  var sig = Signature.fromRS(BigInt.zero, BigInt.zero);
  if (curve.n.sign == 0) {
    throw 'Invalid curve';
  }

  var random = Random.secure();
  late List<int> rand;
  var byteLen = curve.bitSize ~/ 8 + 8;

  late BigInt k, kInv;
  while (true) {
    while (true) {
      rand =
          List<int>.generate(byteLen, (i) => random.nextInt(256)); // bytes of k
      k = BigInt.parse(
          List<String>.generate(
              byteLen, (i) => rand[i].toRadixString(16).padLeft(2, '0')).join(),
          radix: 16);

      kInv = k.modInverse(curve.n);

      sig.R = priv.curve.scalarBaseMul(rand).X;
      sig.R = sig.R % curve.n;
      if (sig.R.sign != 0) {
        // valid r
        break;
      }
    }

    var e = bitsToInt(hash, curve.n.bitLength);
    sig.S = priv.D * sig.R;
    sig.S = sig.S + e;
    sig.S = sig.S * kInv;
    sig.S = sig.S % curve.n; // N != 0
    if (sig.S.sign != 0) {
      break;
    }
  }

  return sig;
}

bool verify(PublicKey pub, List<int> hash, Signature sig) {
  var curve = pub.curve;
  var byteLen = (curve.bitSize + 7) ~/ 8;

  if (sig.R.sign <= 0 || sig.S.sign <= 0) {
    return false;
  }

  if (sig.R >= curve.n || sig.S >= curve.n) {
    return false;
  }

  var e = bitsToInt(hash, curve.n.bitLength);
  var w = sig.S.modInverse(curve.n);

  var u1 = e * w;
  u1 = u1 % curve.n;
  var u2 = sig.R * w;
  u2 = u2 % curve.n;

  var hexU1 = u1.toRadixString(16).padLeft(byteLen * 2, '0');
  var hexU2 = u2.toRadixString(16).padLeft(byteLen * 2, '0');
  var p1 = curve.scalarBaseMul(List<int>.generate(hexU1.length ~/ 2,
      (i) => int.parse(hexU1.substring(i * 2, i * 2 + 2), radix: 16)));
  var p2 = curve.scalarMul(
      pub,
      List<int>.generate(hexU2.length ~/ 2,
          (i) => int.parse(hexU2.substring(i * 2, i * 2 + 2), radix: 16)));
  var p = curve.add(p1, p2);

  if (p.X.sign == 0 && p.Y.sign == 0) {
    return false;
  }

  p.X = p.X % curve.n;
  return p.X == sig.R;
}
