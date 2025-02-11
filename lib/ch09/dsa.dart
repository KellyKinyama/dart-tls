import 'huge.dart';

class DsaParams {
  Huge g;
  Huge p;
  Huge q;

  DsaParams(this.g, this.p, this.q);
}

class DsaSignature {
  Huge r;
  Huge s;

  DsaSignature(this.r, this.s);
}
