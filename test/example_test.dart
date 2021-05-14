import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:betro_dart_lib/betro_dart_lib.dart';
import 'dart:convert';

import 'example.dart';

const originalText = 'Hello';

void main() {
  var file = File('test/generateExample.json');
  final jsonDump = file.readAsStringSync(encoding: utf8);
  final json = Example.fromJson(jsonDecode(jsonDump));
  test('Test Master hashes', () async {
    final masterKey = await getMasterKey(json.email, json.password);
    expect(masterKey, json.masterKey);
    final masterHash = await getMasterHash(masterKey, json.password);
    expect(masterHash, json.masterHash);
    final encryptionKey = await getEncryptionKeys(masterKey);
    expect(encryptionKey, json.encryptionKey);
  });

  test('Test symmetric key', () async {
    final masterKey = await getMasterKey(json.email, json.password);
    final encryptionKey = await getEncryptionKeys(masterKey);
    final decryptedSymKey =
        await symDecrypt(encryptionKey, json.sym.encryptedSymKey);
    final decryptedMessage = await symDecrypt(
        base64Encode(decryptedSymKey), json.sym.encryptedSymMessage);
    expect(Utf8Decoder().convert(decryptedMessage), originalText);
  });

  test('Test rsa key', () async {
    final masterKey = await getMasterKey(json.email, json.password);
    final encryptionKey = await getEncryptionKeys(masterKey);
    final decryptedRsaPrivateKey =
        await symDecrypt(encryptionKey, json.rsa.encryptedPrivateKey);
    final decryptedMessage = await rsaDecrypt(
        base64Encode(decryptedRsaPrivateKey), json.rsa.encryptedRsaMessage);
    expect(Utf8Decoder().convert(decryptedMessage), originalText);
  });

  test("Test ecdh key", () async {
    final masterKey = await getMasterKey(json.email, json.password);
    final encryptionKey = await getEncryptionKeys(masterKey);
    final decryptedEcdhPrivateKey1 =
        await symDecrypt(encryptionKey, json.ecdh.keys[0].encryptedPrivateKey);
    final decryptedEcdhPrivateKey2 =
        await symDecrypt(encryptionKey, json.ecdh.keys[1].encryptedPrivateKey);
    final derivedKey1 = await deriveExchangeSymKey(
        json.ecdh.keys[1].publicKey, base64Encode(decryptedEcdhPrivateKey1));
    final derivedKey2 = await deriveExchangeSymKey(
        json.ecdh.keys[0].publicKey, base64Encode(decryptedEcdhPrivateKey2));
    final edchDerivedKey =
        await symDecrypt(encryptionKey, json.ecdh.ecdhEncryptedSymKey);
    expect(derivedKey1, derivedKey2);
    expect(base64Encode(edchDerivedKey), derivedKey1);
    final decryptedEcdhMessage =
        await symDecrypt(derivedKey1, json.ecdh.ecdhDerivedKeyMessage);
    expect(Utf8Decoder().convert(decryptedEcdhMessage), originalText);
  });
}
