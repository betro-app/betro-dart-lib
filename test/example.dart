import 'package:json_annotation/json_annotation.dart';
part 'example.g.dart';

@JsonSerializable()
class ExampleSym {
  String encryptedSymKey = "";
  String encryptedSymMessage = "";
  ExampleSym();
  factory ExampleSym.fromJson(Map<String, dynamic> json) =>
      _$ExampleSymFromJson(json);
  Map<String, dynamic> toJson() => _$ExampleSymToJson(this);
}

@JsonSerializable()
class ExampleRsa {
  String publicKey = "";
  String encryptedPrivateKey = "";
  String encryptedRsaMessage = "";
  ExampleRsa();

  factory ExampleRsa.fromJson(Map<String, dynamic> json) =>
      _$ExampleRsaFromJson(json);
  Map<String, dynamic> toJson() => _$ExampleRsaToJson(this);
}

@JsonSerializable()
class ExampleEcdhKey {
  String publicKey = "";
  String encryptedPrivateKey = "";
  ExampleEcdhKey({this.publicKey = "", this.encryptedPrivateKey = ""});

  factory ExampleEcdhKey.fromJson(Map<String, dynamic> json) =>
      _$ExampleEcdhKeyFromJson(json);
  Map<String, dynamic> toJson() => _$ExampleEcdhKeyToJson(this);
}

@JsonSerializable()
class ExampleEcdh {
  String ecdhDerivedKeyMessage = "";
  List<ExampleEcdhKey> keys = [];
  ExampleEcdh();

  factory ExampleEcdh.fromJson(Map<String, dynamic> json) =>
      _$ExampleEcdhFromJson(json);
  Map<String, dynamic> toJson() => _$ExampleEcdhToJson(this);
}

@JsonSerializable()
class Example {
  String email = "";
  String password = "";
  String masterKey = "";
  String encryptionKey = "";
  String masterHash = "";
  ExampleSym sym = new ExampleSym();
  ExampleRsa rsa = new ExampleRsa();
  ExampleEcdh ecdh = new ExampleEcdh();

  Example();
  factory Example.fromJson(Map<String, dynamic> json) =>
      _$ExampleFromJson(json);
  Map<String, dynamic> toJson() => _$ExampleToJson(this);
}
