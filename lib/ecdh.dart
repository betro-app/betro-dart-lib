import 'dart:convert';
import 'package:pinenacl/api.dart';
import 'package:pinenacl/src/authenticated_encryption/public.dart';
import 'get_key.dart';

class EcPair {
  final String publicKey;
  final String privateKey;
  EcPair(this.publicKey, this.privateKey);
}

Future<EcPair> generateExchangePair() async {
  final private_key = PrivateKey.generate();
  final publicKey = base64Encode(private_key.publicKey.toList());
  final privateKey = base64Encode(private_key.toList());
  return EcPair(publicKey, privateKey);
}

Future<String> deriveExchangeSymKey(
    String public_key, String private_key) async {
  final privateKey = PrivateKey(base64Decode(private_key));
  final publicKey = PublicKey(base64Decode(public_key));
  final box = Box(myPrivateKey: privateKey, theirPublicKey: publicKey);
  return getEncryptionKeys(base64Encode(box.buffer.asUint8List()));
}
