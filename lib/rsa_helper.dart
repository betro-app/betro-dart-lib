import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import "package:asn1lib/asn1lib.dart";
import 'package:pointycastle/export.dart';

/// Helper class to handle RSA key generation, encoding, decoding, encrypting & decrypting strings
class RsaKeyHelper {
  /// Generates a [SecureRandom] to use in computing RSA key pair
  ///
  /// Returns [FortunaRandom] to be used in the [AsymmetricKeyPair] generation
  SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(new KeyParameter(new Uint8List.fromList(seeds)));
    return secureRandom;
  }

  /// Decode Public key from PEM Format
  ///
  /// Given a base64 encoded PEM [String] with correct headers and footers, return a
  /// [RSAPublicKey]
  ///
  /// *PKCS1*
  /// RSAPublicKey ::= SEQUENCE {
  ///    modulus           INTEGER,  -- n
  ///    publicExponent    INTEGER   -- e
  /// }
  ///
  /// *PKCS8*
  /// PublicKeyInfo ::= SEQUENCE {
  ///   algorithm       AlgorithmIdentifier,
  ///   PublicKey       BIT STRING
  /// }
  ///
  /// AlgorithmIdentifier ::= SEQUENCE {
  ///   algorithm       OBJECT IDENTIFIER,
  ///   parameters      ANY DEFINED BY algorithm OPTIONAL
  /// }
  RSAPublicKey parsePublicKeyFromPem(pemString) {
    Uint8List publicKeyDER = decodePEM(pemString);
    var asn1Parser = new ASN1Parser(publicKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus, exponent;
    // Depending on the first element type, we either have PKCS1 or 2
    if (topLevelSeq.elements[0].runtimeType == ASN1Integer) {
      modulus = topLevelSeq.elements[0] as ASN1Integer;
      exponent = topLevelSeq.elements[1] as ASN1Integer;
    } else {
      var publicKeyBitString = topLevelSeq.elements[1];

      var publicKeyAsn =
          new ASN1Parser(publicKeyBitString.contentBytes() as Uint8List);
      ASN1Sequence publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
      modulus = publicKeySeq.elements[0] as ASN1Integer;
      exponent = publicKeySeq.elements[1] as ASN1Integer;
    }

    RSAPublicKey rsaPublicKey =
        RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);

    return rsaPublicKey;
  }

  /// Sign plain text with Private Key
  ///
  /// Given a plain text [String] and a [RSAPrivateKey], decrypt the text using
  /// a [RSAEngine] cipher
  String sign(String plainText, RSAPrivateKey privateKey) {
    var signer = RSASigner(SHA256Digest(), "0609608648016503040201");
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    return base64Encode(
        signer.generateSignature(createUint8ListFromString(plainText)).bytes);
  }

  /// Creates a [Uint8List] from a string to be signed
  Uint8List createUint8ListFromString(String s) {
    var codec = Utf8Codec(allowMalformed: true);
    return Uint8List.fromList(codec.encode(s));
  }

  /// Decode Private key from PEM Format
  ///
  /// Given a base64 encoded PEM [String] with correct headers and footers, return a
  /// [RSAPrivateKey]
  RSAPrivateKey parsePrivateKeyFromPem(pemString) {
    Uint8List privateKeyDER = decodePEM(pemString);
    var asn1Parser = new ASN1Parser(privateKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus, privateExponent, p, q;
    //Use either PKCS1 or PKCS8 depending on the number of ELEMENTS
    if (topLevelSeq.elements.length == 3) {
      var privateKey = topLevelSeq.elements[2];
      final contentBytes = privateKey.contentBytes();
      if (contentBytes != null) {
        asn1Parser = new ASN1Parser(contentBytes);
        var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

        modulus = pkSeq.elements[1] as ASN1Integer;
        privateExponent = pkSeq.elements[3] as ASN1Integer;
        p = pkSeq.elements[4] as ASN1Integer;
        q = pkSeq.elements[5] as ASN1Integer;
      }
    } else {
      modulus = topLevelSeq.elements[1] as ASN1Integer;
      privateExponent = topLevelSeq.elements[3] as ASN1Integer;
      p = topLevelSeq.elements[4] as ASN1Integer;
      q = topLevelSeq.elements[5] as ASN1Integer;
    }

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
        modulus.valueAsBigInteger,
        privateExponent.valueAsBigInteger,
        p.valueAsBigInteger,
        q.valueAsBigInteger);

    return rsaPrivateKey;
  }

  Uint8List decodePEM(String pem) {
    return base64.decode(removePemHeaderAndFooter(pem));
  }

  String removePemHeaderAndFooter(String pem) {
    var startsWith = [
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN RSA PUBLIC KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
    ];
    var endsWith = [
      "-----END PUBLIC KEY-----",
      "-----END PRIVATE KEY-----",
      "-----END RSA PRIVATE KEY-----",
      "-----END RSA PUBLIC KEY-----",
      "-----END PGP PUBLIC KEY BLOCK-----",
      "-----END PGP PRIVATE KEY BLOCK-----",
    ];
    bool isOpenPgp = pem.indexOf('BEGIN PGP') != -1;

    pem = pem.replaceAll(' ', '');
    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    for (var s in startsWith) {
      s = s.replaceAll(' ', '');
      if (pem.startsWith(s)) {
        pem = pem.substring(s.length);
      }
    }

    for (var s in endsWith) {
      s = s.replaceAll(' ', '');
      if (pem.endsWith(s)) {
        pem = pem.substring(0, pem.length - s.length);
      }
    }

    if (isOpenPgp) {
      var index = pem.indexOf('\r\n');
      pem = pem.substring(0, index);
    }

    return pem;
  }

  /// Encode Private key to PEM Format
  ///
  /// Given [RSAPrivateKey] returns a base64 encoded [String] with standard PEM headers and footers
  String encodePrivateKeyToPemPKCS1(RSAPrivateKey privateKey) {
    var topLevel = new ASN1Sequence();

    var version = ASN1Integer(BigInt.from(0));
    var modulus = ASN1Integer(privateKey.n as BigInt);
    var publicExponent = ASN1Integer(privateKey.exponent as BigInt);
    var privateExponent = ASN1Integer(privateKey.privateExponent as BigInt);
    var p = ASN1Integer(privateKey.p as BigInt);
    var q = ASN1Integer(privateKey.q as BigInt);
    var dP = (privateKey.privateExponent as BigInt) %
        ((privateKey.p as BigInt) - BigInt.from(1));
    var exp1 = ASN1Integer(dP);
    var dQ = (privateKey.privateExponent as BigInt) %
        ((privateKey.q as BigInt) - BigInt.from(1));
    var exp2 = ASN1Integer(dQ);
    var iQ = (privateKey.q as BigInt).modInverse(privateKey.p as BigInt);
    var co = ASN1Integer(iQ);

    topLevel.add(version);
    topLevel.add(modulus);
    topLevel.add(publicExponent);
    topLevel.add(privateExponent);
    topLevel.add(p);
    topLevel.add(q);
    topLevel.add(exp1);
    topLevel.add(exp2);
    topLevel.add(co);

    var dataBase64 = base64.encode(topLevel.encodedBytes);

    return dataBase64;
  }

  /// Encode Public key to PEM Format
  ///
  /// Given [RSAPublicKey] returns a base64 encoded [String] with standard PEM headers and footers
  String encodePublicKeyToPemPKCS1(RSAPublicKey publicKey) {
    var topLevel = new ASN1Sequence();

    topLevel.add(ASN1Integer(publicKey.modulus as BigInt));
    topLevel.add(ASN1Integer(publicKey.exponent as BigInt));

    var dataBase64 = base64.encode(topLevel.encodedBytes);
    return dataBase64;
  }
}

/// Encrypting String
Uint8List encrypt(RSAPublicKey publicKey, Uint8List plaintext) {
  var cipher = new OAEPEncoding(RSAEngine())
    ..init(true, new PublicKeyParameter<RSAPublicKey>(publicKey));
  var cipherText = cipher.process(plaintext);

  return cipherText;
}

/// Decrypting String
Uint8List decrypt(RSAPrivateKey privateKey, Uint8List ciphertext) {
  var cipher = new OAEPEncoding(RSAEngine())
    ..init(false, new PrivateKeyParameter<RSAPrivateKey>(privateKey));
  var decrypted = cipher.process(ciphertext);

  return decrypted;
}

/// Generate a [PublicKey] and [PrivateKey] pair
///
/// Returns a [AsymmetricKeyPair] based on the [RSAKeyGenerator] with custom parameters,
/// including a [SecureRandom]
AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> getRsaKeyPair(
    SecureRandom secureRandom) {
  /// Set BitStrength to [1024, 2048 or 4096]
  var rsapars = new RSAKeyGeneratorParameters(BigInt.from(65537), 4096, 5);
  var params = new ParametersWithRandom(rsapars, secureRandom);
  var keyGenerator = new RSAKeyGenerator();
  keyGenerator.init(params);
  final keyPair = keyGenerator.generateKeyPair();
  final RSAPublicKey publicKey = keyPair.publicKey as RSAPublicKey;
  final RSAPrivateKey privateKey = keyPair.privateKey as RSAPrivateKey;
  return new AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      publicKey, privateKey);
}
