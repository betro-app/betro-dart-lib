import 'package:cryptography/cryptography.dart';
import 'package:encrypt/encrypt.dart';
import 'package:collection/collection.dart';
import 'dart:convert';
import 'dart:math';

String generateSymKey() {
  var random = Random.secure();
  var values = List<int>.generate(32, (i) => random.nextInt(256));
  var mac = List<int>.generate(32, (i) => random.nextInt(256));
  List<int> buf = [];
  buf.addAll(values);
  buf.addAll(mac);
  return base64Encode(buf);
}

Future<String> symEncrypt(String sym_key, List<int> data) async {
  final buf = base64Decode(sym_key);
  final keyBuffer = buf.sublist(0, 32);
  final key = new Key(keyBuffer);
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
    secretKey: SecretKey(buf.sublist(32)),
  );
  final macBytes = mac.bytes;
  final List<int> encryptedMsg = macBytes + ivBytes + encryptedData;
  return base64Encode(encryptedMsg);
}

Future<List<int>> symDecrypt(String sym_key, String encrypted) async {
  final encryptedMsg = base64Decode(encrypted);
  final macBytes = encryptedMsg.sublist(0, 32);
  final message = encryptedMsg.sublist(32);
  final ivBytes = encryptedMsg.sublist(32, 48);
  final encryptedData = encryptedMsg.sublist(48);

  final buf = base64Decode(sym_key);
  final hmac = Hmac.sha256();
  final mac = await hmac.calculateMac(
    message,
    secretKey: SecretKey(
      buf.sublist(32),
    ),
  );
  Function eq = const ListEquality().equals;
  if (!eq(mac.bytes, macBytes)) {
    return [];
  }
  final keyBuffer = buf.sublist(0, 32);
  final key = new Key(keyBuffer);
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
