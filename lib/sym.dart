import 'package:encrypt/encrypt.dart';
import 'dart:convert';
import 'dart:math';

String generateSymKey() {
  var random = Random.secure();
  var values = List<int>.generate(32, (i) => random.nextInt(256));
  return base64Encode(values);
}

String symEncrypt(String sym_key, List<int> data) {
  final key = Key.fromBase64(sym_key);
  final iv = IV.fromLength(16);
  final encrypter = Encrypter(
    AES(
      key,
      mode: AESMode.cbc,
    ),
  );
  final encrypted = encrypter.encryptBytes(data, iv: iv);
  final encryptedData = encrypted.bytes;
  final List<int> message = iv.bytes + encryptedData;
  return base64Encode(message);
}

List<int> symDecrypt(String sym_key, String encrypted) {
  final encryptedMsg = base64Decode(encrypted);
  final ivBytes = encryptedMsg.sublist(0, 16);
  final encryptedData = encryptedMsg.sublist(16);
  final key = Key.fromBase64(sym_key);
  final encrypter = Encrypter(
    AES(
      key,
      mode: AESMode.cbc,
    ),
  );
  final decrypted = encrypter.decryptBytes(
    Encrypted.fromBase64(base64Encode(encryptedData)),
    iv: IV.fromBase64(
      base64Encode(ivBytes),
    ),
  );
  return decrypted;
}
