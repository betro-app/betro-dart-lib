import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:encrypt/encrypt.dart';
import 'package:collection/collection.dart';

Future<String> aesEncrypt(
    String encryptionKey, String encryptionMac, List<int> data) async {
  final key = Key.fromBase64(encryptionKey);
  final iv = IV.fromLength(16);
  final encrypter = Encrypter(
    AES(
      key,
      mode: AESMode.cbc,
    ),
  );
  final encrypted = encrypter.encryptBytes(data, iv: iv);
  final encryptedData = encrypted.bytes;
  final ivBytes = iv.bytes;
  final List<int> message = ivBytes + encryptedData;
  final hmac = Hmac.sha256();
  final mac = await hmac.calculateMac(
    message,
    secretKey: SecretKey(
      base64Decode(encryptionMac),
    ),
  );
  final macBytes = mac.bytes;
  final List<int> encryptedMsg = macBytes + ivBytes + encryptedData;
  return base64Encode(encryptedMsg);
}

Future<List<int>> aesDecrypt(
    String encryptionKey, String encryptionMac, String encrypted) async {
  final encryptedMsg = base64Decode(encrypted);
  final macBytes = encryptedMsg.sublist(0, 32);
  final message = encryptedMsg.sublist(32);
  final ivBytes = encryptedMsg.sublist(32, 48);
  final encryptedData = encryptedMsg.sublist(48);

  final hmac = Hmac.sha256();
  final mac = await hmac.calculateMac(
    message,
    secretKey: SecretKey(
      base64Decode(encryptionMac),
    ),
  );
  Function eq = const ListEquality().equals;
  if (!eq(mac.bytes, macBytes)) {
    return [];
  }
  final key = Key.fromBase64(encryptionKey);
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
