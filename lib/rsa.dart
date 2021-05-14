import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';

class RsaPair {
  final String publicKey;
  final String privateKey;
  RsaPair(this.publicKey, this.privateKey);
}

Future<RsaPair> generateRsaPair() async {
  final keyPair =
      await RsaOaepPrivateKey.generateKey(2048, BigInt.from(3), Hash.sha256);
  final privateKey = base64Encode(await keyPair.privateKey.exportPkcs8Key());
  final publicKey = base64Encode(await keyPair.publicKey.exportSpkiKey());
  return RsaPair(publicKey, privateKey);
}

Future<String> rsaEncrypt(String publicKey, List<int> data) async {
  final key = await RsaOaepPublicKey.importSpkiKey(
      base64Decode(publicKey), Hash.sha256);
  return base64Encode(await key.encryptBytes(data));
}

Future<List<int>> rsaDecrypt(String privateKey, String encrypted) async {
  final key = await RsaOaepPrivateKey.importPkcs8Key(
      base64Decode(privateKey), Hash.sha256);
  final bytes = await key.decryptBytes(base64Decode(encrypted));
  return bytes.toList();
}
