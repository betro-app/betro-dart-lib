import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';
import 'get_key.dart';

class EcPair {
  final String publicKey;
  final String privateKey;
  EcPair(this.publicKey, this.privateKey);
}

Future<EcPair> generateExchangePair() async {
  final keyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  final publicKey = base64Encode(await keyPair.publicKey.exportSpkiKey());
  final privateKey = base64Encode(await keyPair.privateKey.exportPkcs8Key());
  return EcPair(publicKey, privateKey);
}

Future<String> deriveExchangeSymKey(
    String public_key, String private_key) async {
  final privateKey = await EcdhPrivateKey.importPkcs8Key(
      base64Decode(private_key), EllipticCurve.p256);
  final publicKey = await EcdhPublicKey.importSpkiKey(
      base64Decode(public_key), EllipticCurve.p256);
  final bits = await privateKey.deriveBits(256, publicKey);
  return getEncryptionKeys(base64Encode(bits));
}
