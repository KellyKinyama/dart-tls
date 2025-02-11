// See for complete overview: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml

// Only TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 was implemented.
// See for further Cipher Suite types: https://www.rfc-editor.org/rfc/rfc8422.html#section-6
typedef CipherSuiteID = int;

// Only NamedCurve was implemented.
// See for further CurveType types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
typedef CurveType = int;

// Only X25519 was implemented.
// See for further NamedCurve types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
typedef Curve = int;

// Only Uncompressed was implemented.
// See for further Elliptic Curve Point Format types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
typedef PointFormat = int;

// Only SHA256 was implemented.
// See for further Hash Algorithm types (in "HashAlgorithm" enum):  https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
typedef HashAlgorithm = int;

// Only ECDSA was implemented.
// See for further Signature Algorithm types: (in "signed_params" bullet, SignatureAlgorithm enum) https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
// See also (in "SignatureAlgorithm" enum): https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
typedef SignatureAlgorithm = int;

// Only ECDSA Sign was implemented.
// See for further ClientCertificateType types (in "ClientCertificateType" enum):  https://www.rfc-editor.org/rfc/rfc8422.html#section-5.5
// See also https://tools.ietf.org/html/rfc5246#section-7.4.4
typedef CertificateType = int;

typedef KeyExchangeAlgorithm = int;

// Only SRTP_AEAD_AES_128_GCM was implemented.
// See for further SRTP Protection Profile types: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
typedef SRTPProtectionProfile = int;

class CipherSuite {
  CipherSuiteID cipherSuiteID;
  KeyExchangeAlgorithm keyExchangeAlgorithm;
  CertificateType certificateType;
  HashAlgorithm hashAlgorithm;
  SignatureAlgorithm signatureAlgorithm;

  CipherSuite(this.cipherSuiteID, this.keyExchangeAlgorithm,
      this.certificateType, this.hashAlgorithm, this.signatureAlgorithm);
}

// const (
// Only TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 was implemented.
// See for further Cipher Suite types: https://www.rfc-editor.org/rfc/rfc8422.html#section-6
CipherSuiteID CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b;

// Only NamedCurve was implemented.
// See for further CurveType types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
CurveType CurveTypeNamedCurve = 0x03;

// Only X25519 was implemented.
// See for further NamedCurve types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
Curve CurveX25519 = 0x001d;

// Only Uncompressed was implemented.
// See for further Elliptic Curve Point Format types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
PointFormat PointFormatUncompressed = 0;

// Only SHA256 was implemented.
// See for further Hash Algorithm types (in "HashAlgorithm" enum):  https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
HashAlgorithm HashAlgorithmSHA256 = 4;

// Only ECDSA was implemented.
// See for further Signature Algorithm types: (in "signed_params" bullet, SignatureAlgorithm enum) https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
// See also (in "SignatureAlgorithm" enum): https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
SignatureAlgorithm SignatureAlgorithmECDSA = 3;

// Only ECDSA Sign was implemented.
// See for further ClientCertificateType types (in "ClientCertificateType" enum):  https://www.rfc-editor.org/rfc/rfc8422.html#section-5.5
// See also https://tools.ietf.org/html/rfc5246#section-7.4.4
CertificateType CertificateTypeECDSASign = 64;

KeyExchangeAlgorithm KeyExchangeAlgorithmNone = 0; //Value is not important
KeyExchangeAlgorithm KeyExchangeAlgorithmECDHE = 1; //Value is not important

// Only SRTP_AEAD_AES_128_GCM was implemented.
// See for further SRTP Protection Profile types: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
SRTPProtectionProfile SRTPProtectionProfile_AEAD_AES_128_GCM = 0x0007;
// )

final supportedCurves = {
  CurveX25519: true,
};

final supportedSRTPProtectionProfiles = {
  SRTPProtectionProfile_AEAD_AES_128_GCM: true,
};

final supportedCipherSuites = {
  CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: (
    CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    KeyExchangeAlgorithmECDHE,
    CertificateTypeECDSASign,
    HashAlgorithmSHA256,
    SignatureAlgorithmECDSA,
  ),
};
