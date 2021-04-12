import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:betro_dart_lib/betro_dart_lib.dart';

const originalText = "Hello";

void main() {
  const MethodChannel channel = MethodChannel('betro_dart_lib');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await BetroDartLib.platformVersion, '42');
  });

  test("Master Key", () async {
    final master_key = await getMasterKey("user@example.com", "123456");
    expect(master_key, "3idIphVUYcefUgjLnsJLaBD+uKSNCM0c8W6lwmsqwAA=");
  });

  test("Encryption Keys", () async {
    final master_key = await getMasterKey("user@example.com", "123456");
    final encryptionKeys = await getEncryptionKeys(master_key);

    final encryptionKey = encryptionKeys.encryptionKey;
    final encryptionMac = encryptionKeys.encryptionMac;
    expect(encryptionKey, "s1YlR3RY/vR1jlx4mbxhGUvtMDxN30iMzOzFRXlGzpY=");
    expect(encryptionMac, "qtu7PgAC4yB2hdvmQLzaw0a7IpHoMIvTXHuhBxKmtw8=");
  });

  test("Master hash", () async {
    final master_key = await getMasterKey("user@example.com", "123456");
    final master_hash = await getMasterHash(master_key, "123456");
    expect(master_hash, "wXINGBwxrsp93A1vhLMGsSx1Cjwd3Do7dNAkoaiykeU=");
  });

  test("Aes encryption", () async {
    final master_key = await getMasterKey("user@example.com", "123456");
    final encryptionKeys = await getEncryptionKeys(master_key);
    final master_hash = await getMasterHash(master_key, "123456");

    final encryptionKey = encryptionKeys.encryptionKey;
    final encryptionMac = encryptionKeys.encryptionMac;

    final encrypted = await aesEncrypt(
        encryptionKey, encryptionMac, Utf8Encoder().convert(originalText));

    final decrypted = await aesDecrypt(encryptionKey, encryptionMac, encrypted);
    expect(decrypted, Utf8Encoder().convert(originalText));

    expect(
      await aesDecrypt(encryptionKey, encryptionMac,
          "yWddnLg/ErUkIxVvJ4cx/hjFwEtezipk+VM8IfVuhIiaU9EZxMusfmsNslqC4jLn65NzHSublXsfmATj+3JbSA=="),
      Utf8Encoder().convert(originalText),
    );
  });

  test("Sym key", () async {
    final symKey = await generateSymKey();

    final symEncrypted =
        await symEncrypt(symKey, Utf8Encoder().convert(originalText));

    final symDecrypted = await symDecrypt(symKey, symEncrypted);
    expect(symDecrypted, Utf8Encoder().convert(originalText));
  });

  test("Sym key decryption", () async {
    final symKey = "aKBB9Cgw6VYa+hSGGDFCdM8tLfmLYtLzjOLah1RMaiw=";
    final symEncrypted = "PjdYU19kzydZagXb/a0hV/3X2ONKmuJ0Vp1u6Okse3A=";
    final symDecrypted = await symDecrypt(symKey, symEncrypted);
    expect(symDecrypted, Utf8Encoder().convert(originalText));
  });

  test("Rsa key", () async {
    final rsaKeys = await generateRsaPair();
    final publicKey = rsaKeys.publicKey;
    final privateKey = rsaKeys.privateKey;

    final rsaEncrypted =
        await rsaEncrypt(publicKey, Utf8Encoder().convert(originalText));
    final rsaDecrypted = await rsaDecrypt(privateKey, rsaEncrypted);
    expect(Utf8Decoder().convert(rsaDecrypted), originalText);
  });

  test("Rsa decryption", () async {
    const publicKey =
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsVEtAoG7CGmVud8hZnYPKZUQhHP3LjGpQI9GVRSRwyz33zcy7brRYGa5VXB4ZjIu96XhtCZo5TXzKVxdCySGtjwhCaGFt6iKE3uqsHbjfnTB4y2jrH4KIDZ/DQPj4iwxWhY7lGcn+fl9AennU3DWzuRYEes8KN3ywbJJAhy3lu090a/PAdPYWeVDGIsW4pZK4DfdqYoBxXLA66NSfD3RTuD1GEzPoAMtXBcYeJFqY4LGDuR5UVu801lpNSphYytYzIYanVp6jxwBSIGdRVppixswyvkzsNdodT9YA2c7QaZVRXoiaGvmwHbmXjreaOtPOU+q6uq/54ARtKC3ATofbsIVwiShqUwMoH9q20n1FcKooh5I8VdhNb7FhKLqVsNHn/gvX2fkc6zHjRQ0kGQJdMm3YWD1kfAARxNXT5IzCO7etxEvjp1XoKNBCMhu5K+1BZicHr9XwuslgfaqCdrXffAtBiLeblBuV7mCrhzgJsAkdeQ0a4HdX5uSSwnEl4x/ZgLg+jiPk5vKgfTxvsL0d/gqsr4NHb1i5r8u/edRfwd75Q8teXgtn6n/91CvFrrRDZzu38u+xEkhE4nTOS24O4evo9EXhQ2JMZENLwzxNniNBVheu9Nx+Z1DL2Sn1F8KhiC4RsgTij59Im1xfPWs3NKcEk61KSO/GlWGI48hgCkCAwEAAQ==";
    final privateKey =
        "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";
    final rsaEncryptedFromjs =
        "SU2/A8bxJ+H5dLdgAQPkuSC1KGBQ8Xg5kAWAwf4qbq/cDwPnTTTx6JLMeNBiLpGfw1EBshoDCuMLZ4GAJW93BWVWEtW/gzVxc1hP77+8vc+y3EJ1BjiLOV0MUYllMeDWjApKqPDKG4lBdrGpnkwRusHtvjE4oDpejJ4S5x57CqZIszSeyFxTTTGSUkdnkX2ow9JKApodbz2+LvLKTIOS+zGYKWAo9MfQ8+/zXnkNhRObbsoLky/I1ezWIhk2gtzVmxN0ozbXjrM7vAVZmb4lwIQogxrlq2DKpHP2X8AW4dOJ+jGdyKKVZ9H5Fjc+MMrueJ8Y09DxqRp3AprMuaQ0UgYiBmad5i5UaMOVSFeXnSrqA+vUDzc3mIQPy6RuY2Q5ouOTr6LtOpUmHwOfEeFEnB4r5vdVuWeDsaiJfIiwOyPUKZaYks7Nf3rsqLGJsHDq9yntMCL3ZmhS0Yzbg2l9TTSNjgs89BlDPJE8lKvK5uZkOScbKN53wVppYROy6NfT3RpwqtZjUrQc8w8WzoAJLiJOg4ajyrcbNyQZN/J9hyRhilB/W2uS4vfzAV6QJPd955+RimMvCpANhNjoDtV1Ksy5zlCZrU497YRBbx3ZxDVevL5PNH3hGzZWbcLxyRhFEOCGyskkhEO5uIPK/248JBbUYQ5JJyaKOAeORayAHR8=";

    final rsaEncrypted =
        await rsaEncrypt(publicKey, Utf8Encoder().convert(originalText));
    final rsaDecrypted = await rsaDecrypt(privateKey, rsaEncrypted);
    expect(Utf8Decoder().convert(rsaDecrypted), originalText);
    final rsaDecryptedJs = await rsaDecrypt(privateKey, rsaEncryptedFromjs);
    expect(Utf8Decoder().convert(rsaDecryptedJs), originalText);
  });
}
