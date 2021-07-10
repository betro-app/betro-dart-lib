import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';
import 'constants.dart';

Future<EcPair> generateEcdsaPair() async {
  final keyPair = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
  final publicKey = base64Encode(await keyPair.publicKey.exportSpkiKey());
  final privateKey = base64Encode(await keyPair.privateKey.exportPkcs8Key());
  return EcPair(publicKey, privateKey);
}

Future<String> signEcdsa(String private_key, List<int> data) async {
  final key = await EcdsaPrivateKey.importPkcs8Key(
      base64Decode(private_key), EllipticCurve.p256);
  return base64Encode(await key.signBytes(data, Hash.sha256));
}

Future<bool> verifyEcdsa(
    String public_key, List<int> data, String signature) async {
  final key = await EcdsaPublicKey.importSpkiKey(
      base64Decode(public_key), EllipticCurve.p256);
  return key.verifyBytes(base64Decode(signature), data, Hash.sha256);
}
