import 'dart:io';
import 'dart:convert';
import 'package:betro_dart_lib/betro_dart_lib.dart';
import 'example.dart';

const originalText = "Hello";

void main() async {
  const email = "user2@example.com";
  const password = "123456";
  final masterKey = await getMasterKey(email, password);
  final encryptionKey = await getEncryptionKeys(masterKey);
  final masterHash = await getMasterHash(masterKey, password);

  final symKey = await generateSymKey();
  final encryptedSymKey = await symEncrypt(encryptionKey, base64Decode(symKey));
  final encryptedSymMessage =
      await symEncrypt(symKey, Utf8Encoder().convert(originalText));

  final rsaKeys = await generateRsaPair();
  final encryptedRsaPrivateKey =
      await symEncrypt(encryptionKey, base64Decode(rsaKeys.privateKey));
  final encryptedRsaMessage =
      await rsaEncrypt(rsaKeys.publicKey, Utf8Encoder().convert(originalText));

  final ecdhPair1 = await generateExchangePair();
  final ecdhPair2 = await generateExchangePair();
  final ecdhDerivedKey =
      await deriveExchangeSymKey(ecdhPair1.publicKey, ecdhPair2.privateKey);
  final ecdhDerivedKeyMessage =
      await symEncrypt(ecdhDerivedKey, Utf8Encoder().convert(originalText));

  final encryptedEcdhPrivateKey1 =
      await symEncrypt(encryptionKey, base64Decode(ecdhPair1.privateKey));
  final encryptedEcdhPrivateKey2 =
      await symEncrypt(encryptionKey, base64Decode(ecdhPair2.privateKey));

  final example = new Example();
  example.email = email;
  example.password = password;
  example.masterKey = masterKey;
  example.encryptionKey = encryptionKey;
  example.masterHash = masterHash;
  example.sym.encryptedSymKey = encryptedSymKey;
  example.sym.encryptedSymMessage = encryptedSymMessage;
  example.rsa.publicKey = rsaKeys.publicKey;
  example.rsa.encryptedPrivateKey = encryptedRsaPrivateKey;
  example.rsa.encryptedRsaMessage = encryptedRsaMessage;
  example.ecdh.ecdhDerivedKeyMessage = ecdhDerivedKeyMessage;
  example.ecdh.keys.add(
    new ExampleEcdhKey(
      publicKey: ecdhPair1.publicKey,
      encryptedPrivateKey: encryptedEcdhPrivateKey1,
    ),
  );
  example.ecdh.keys.add(
    new ExampleEcdhKey(
      publicKey: ecdhPair2.publicKey,
      encryptedPrivateKey: encryptedEcdhPrivateKey2,
    ),
  );
  var file = new File("test/generateExample.json");
  file.writeAsString(JsonEncoder.withIndent('  ').convert(example.toJson()));
}
