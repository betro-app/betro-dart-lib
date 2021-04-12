import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'constants.dart';

Future<String> getMasterHash(String master_key, String password) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: ITERATIONS,
    bits: HASH_LENGTH,
  );

  final secretKey = SecretKey(Utf8Encoder().convert(master_key));
  final salt = Utf8Encoder().convert(password);

  final newSecretKey =
      await pbkdf2.deriveKey(secretKey: secretKey, nonce: salt);
  final newSecretKeyBytes = await newSecretKey.extractBytes();

  return base64Encode(newSecretKeyBytes);
}
