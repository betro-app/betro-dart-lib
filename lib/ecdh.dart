import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'get_key.dart';

class EcPair {
  final String publicKey;
  final String privateKey;
  EcPair(this.publicKey, this.privateKey);
}

Future<EcPair> generateExchangePair() async {
  final algorithm = Cryptography.instance.x25519();
  final keyPair = await algorithm.newKeyPair();

  final publicKey = base64Encode((await keyPair.extractPublicKey()).bytes);

  final privateKey = base64Encode(await keyPair.extractPrivateKeyBytes());

  return EcPair(publicKey, privateKey);
}

Future<String> deriveExchangeSymKey(
    String public_key, String private_key) async {
  final publicKey =
      SimplePublicKey(base64Decode(public_key), type: KeyPairType.x25519);
  final privateKey = base64Decode(private_key);
  final algorithm = Cryptography.instance.x25519();
  // algorithm.keyPairType;
  final keyPair = await algorithm.newKeyPairFromSeed(privateKey);
  final secretKey = await algorithm.sharedSecretKey(
      keyPair: keyPair, remotePublicKey: publicKey);
  return getEncryptionKeys(base64Encode(await secretKey.extractBytes()));
}
