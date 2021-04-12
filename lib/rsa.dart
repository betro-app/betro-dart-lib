import 'dart:convert';
import 'dart:typed_data';
import 'rsa_helper.dart';

class RsaPair {
  final String publicKey;
  final String privateKey;
  RsaPair(this.publicKey, this.privateKey);
}

final rsaKeyHelper = RsaKeyHelper();

RsaPair generateRsaPair() {
  var keyPair = getRsaKeyPair(rsaKeyHelper.getSecureRandom());
  final publicKey = rsaKeyHelper.encodePublicKeyToPemPKCS1(keyPair.publicKey);
  final privateKey =
      rsaKeyHelper.encodePrivateKeyToPemPKCS1(keyPair.privateKey);
  return RsaPair(publicKey, privateKey);
}

Future<String> rsaEncrypt(String publicKey, List<int> data) async {
  final pKey = rsaKeyHelper.parsePublicKeyFromPem(publicKey);
  return base64Encode(
    encrypt(pKey, new Uint8List.fromList(data)),
  );
}

List<int> rsaDecrypt(String privateKey, String encrypted) {
  final pKey = rsaKeyHelper.parsePrivateKeyFromPem(privateKey);
  return decrypt(
    pKey,
    base64Decode(encrypted),
  );
}
