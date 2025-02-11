class DsaParams {
  BigInt g;
  BigInt p;
  BigInt q;

  DsaParams(this.g, this.p, this.q);
}

class DsaSignature {
  BigInt r;
  BigInt s;

  DsaSignature(this.r, this.s);
}