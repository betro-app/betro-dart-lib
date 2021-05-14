// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'example.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ExampleSym _$ExampleSymFromJson(Map<String, dynamic> json) {
  return ExampleSym()
    ..encryptedSymKey = json['encryptedSymKey'] as String
    ..encryptedSymMessage = json['encryptedSymMessage'] as String;
}

Map<String, dynamic> _$ExampleSymToJson(ExampleSym instance) =>
    <String, dynamic>{
      'encryptedSymKey': instance.encryptedSymKey,
      'encryptedSymMessage': instance.encryptedSymMessage,
    };

ExampleRsa _$ExampleRsaFromJson(Map<String, dynamic> json) {
  return ExampleRsa()
    ..publicKey = json['publicKey'] as String
    ..encryptedPrivateKey = json['encryptedPrivateKey'] as String
    ..encryptedRsaMessage = json['encryptedRsaMessage'] as String;
}

Map<String, dynamic> _$ExampleRsaToJson(ExampleRsa instance) =>
    <String, dynamic>{
      'publicKey': instance.publicKey,
      'encryptedPrivateKey': instance.encryptedPrivateKey,
      'encryptedRsaMessage': instance.encryptedRsaMessage,
    };

ExampleEcdhKey _$ExampleEcdhKeyFromJson(Map<String, dynamic> json) {
  return ExampleEcdhKey(
    publicKey: json['publicKey'] as String,
    encryptedPrivateKey: json['encryptedPrivateKey'] as String,
  );
}

Map<String, dynamic> _$ExampleEcdhKeyToJson(ExampleEcdhKey instance) =>
    <String, dynamic>{
      'publicKey': instance.publicKey,
      'encryptedPrivateKey': instance.encryptedPrivateKey,
    };

ExampleEcdh _$ExampleEcdhFromJson(Map<String, dynamic> json) {
  return ExampleEcdh()
    ..ecdhDerivedKeyMessage = json['ecdhDerivedKeyMessage'] as String
    ..ecdhEncryptedSymKey = json['ecdhEncryptedSymKey'] as String
    ..keys = (json['keys'] as List<dynamic>)
        .map((e) => ExampleEcdhKey.fromJson(e as Map<String, dynamic>))
        .toList();
}

Map<String, dynamic> _$ExampleEcdhToJson(ExampleEcdh instance) =>
    <String, dynamic>{
      'ecdhDerivedKeyMessage': instance.ecdhDerivedKeyMessage,
      'ecdhEncryptedSymKey': instance.ecdhEncryptedSymKey,
      'keys': instance.keys,
    };

Example _$ExampleFromJson(Map<String, dynamic> json) {
  return Example()
    ..email = json['email'] as String
    ..password = json['password'] as String
    ..masterKey = json['masterKey'] as String
    ..encryptionKey = json['encryptionKey'] as String
    ..masterHash = json['masterHash'] as String
    ..sym = ExampleSym.fromJson(json['sym'] as Map<String, dynamic>)
    ..rsa = ExampleRsa.fromJson(json['rsa'] as Map<String, dynamic>)
    ..ecdh = ExampleEcdh.fromJson(json['ecdh'] as Map<String, dynamic>);
}

Map<String, dynamic> _$ExampleToJson(Example instance) => <String, dynamic>{
      'email': instance.email,
      'password': instance.password,
      'masterKey': instance.masterKey,
      'encryptionKey': instance.encryptionKey,
      'masterHash': instance.masterHash,
      'sym': instance.sym,
      'rsa': instance.rsa,
      'ecdh': instance.ecdh,
    };
