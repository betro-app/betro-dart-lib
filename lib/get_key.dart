import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'constants.dart';

Future<String> getMasterKey(String email, String password) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: ITERATIONS,
    bits: HASH_LENGTH,
  );

  final secretKey = SecretKey(Utf8Encoder().convert(password));
  final salt = Utf8Encoder().convert(email);

  final newSecretKey =
      await pbkdf2.deriveKey(secretKey: secretKey, nonce: salt);
  final newSecretKeyBytes = await newSecretKey.extractBytes();

  return base64Encode(newSecretKeyBytes);
}

Future<String> getEncryptionKeys(String master_key) async {
  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final secretKey = SecretKey(base64Decode(master_key));
  final nonce = Utf8Encoder().convert("sign");
  final encryptionKey = await algorithm.deriveKey(
    secretKey: secretKey,
    nonce: nonce,
    info: Utf8Encoder().convert("enc"),
  );
  final encryptionMac = await algorithm.deriveKey(
    secretKey: secretKey,
    nonce: nonce,
    info: Utf8Encoder().convert("mac"),
  );
  List<int> buf = [];
  buf.addAll(await encryptionKey.extractBytes());
  buf.addAll(await encryptionMac.extractBytes());
  return base64Encode(buf);
}
