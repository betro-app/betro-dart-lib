import 'package:flutter_test/flutter_test.dart';
import 'package:betro_dart_lib/betro_dart_lib.dart';
import 'dart:convert';

const originalText = 'Hello';

void main() {
  test('Master Key', () async {
    final master_key = await getMasterKey('user@example.com', '123456');
    expect(master_key, '3idIphVUYcefUgjLnsJLaBD+uKSNCM0c8W6lwmsqwAA=');
  });

  test('Encryption Keys', () async {
    final master_key = await getMasterKey('user@example.com', '123456');
    final encryptionKey = await getEncryptionKeys(master_key);

    expect(encryptionKey,
        's1YlR3RY/vR1jlx4mbxhGUvtMDxN30iMzOzFRXlGzpaq27s+AALjIHaF2+ZAvNrDRrsikegwi9Nce6EHEqa3Dw==');
  });

  test('Master hash', () async {
    final master_key = await getMasterKey('user@example.com', '123456');
    final master_hash = await getMasterHash(master_key, '123456');
    expect(master_hash, 'wXINGBwxrsp93A1vhLMGsSx1Cjwd3Do7dNAkoaiykeU=');
  });

  test('Aes encryption', () async {
    final master_key = await getMasterKey('user@example.com', '123456');
    final encryptionKey = await getEncryptionKeys(master_key);

    final encrypted =
        await symEncrypt(encryptionKey, Utf8Encoder().convert(originalText));

    final decrypted = await symDecrypt(encryptionKey, encrypted);
    expect(decrypted, Utf8Encoder().convert(originalText));

    expect(
      await symDecrypt(encryptionKey,
          'NszekqO5MJc++uLtB56aSuXcC8wCicAZsgtYgjnANzT8iMixE7RvMPvacTcIPvgfZsVW+gWhy9jXl8mNZ+30+w=='),
      Utf8Encoder().convert(originalText),
    );
  });

  test('Sym key', () async {
    final symKey = generateSymKey();

    final symEncrypted =
        await symEncrypt(symKey, Utf8Encoder().convert(originalText));

    final symDecrypted = await symDecrypt(symKey, symEncrypted);
    expect(symDecrypted, Utf8Encoder().convert(originalText));
  });

  test('Sym key decryption', () async {
    final symKey =
        'E9kufbmm2Zgf/Q8dr33FOPN9DEFTI/y81NI/db0FHaKKOFPV7PcECmndNSrO3GNh5c3nwBgBsQmXO+FoUGzLMotXtAHTpxRyeYnVxz65U5d8ZEToyqvKcOCsCxQN8Q/k';
    final symEncrypted =
        'lLSXfg83sd1/F8Dji5N1AtME4bks7SVNm7rjKNEhG+YlV92g0Qt8D4XL4LxgByemhrDrwYn6W7NU9B8hrfNPFA==';
    final symDecrypted = await symDecrypt(symKey, symEncrypted);
    expect(symDecrypted, Utf8Encoder().convert(originalText));
  });

  test('Rsa key', () async {
    final rsaKeys = await generateRsaPair();
    final publicKey = rsaKeys.publicKey;
    final privateKey = rsaKeys.privateKey;

    final rsaEncrypted =
        await rsaEncrypt(publicKey, Utf8Encoder().convert(originalText));
    final rsaDecrypted = await rsaDecrypt(privateKey, rsaEncrypted);
    expect(Utf8Decoder().convert(rsaDecrypted), originalText);
  });

  test('Rsa decryption', () async {
    // TODO: No implementation in dart for RSA-OAEP
    const publicKey =
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2fXAg8OJ0WLzsSDf5ZMaVfo+6SFp+FgWx5W9/zT/dI0m1pxS4rTNEcmX5tS8GOikpKQku9WT6A5ugeR+UMeGXIwmLnggDx0TjhgqcrqWSk8X9FGVw8t6D7WORMexP6LLduhKNVCmBrQlcD/HonsbI+9KU2aMMB6QJ31Kgrw1+vi/hoTKWC9sc0vhBqiz+ZGI/Z6FhMaXHn7khRPM/+gHkL6/pt1U9q9uZ9sjwYsxkojQa6TEH8Pywyfg++aLC08/tvJUHrILYWw0A19Wtkw2nj8lQqwXUP+ovBX4X7nwivN8xAzZ/p5aqAisZlSxhyfXUj0quDdL/LeHpV+5OaLyjQIDAQAB';
    final privateKey =
        'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDZ9cCDw4nRYvOxIN/lkxpV+j7pIWn4WBbHlb3/NP90jSbWnFLitM0RyZfm1LwY6KSkpCS71ZPoDm6B5H5Qx4ZcjCYueCAPHROOGCpyupZKTxf0UZXDy3oPtY5Ex7E/ost26Eo1UKYGtCVwP8eiexsj70pTZowwHpAnfUqCvDX6+L+GhMpYL2xzS+EGqLP5kYj9noWExpcefuSFE8z/6AeQvr+m3VT2r25n2yPBizGSiNBrpMQfw/LDJ+D75osLTz+28lQesgthbDQDX1a2TDaePyVCrBdQ/6i8FfhfufCK83zEDNn+nlqoCKxmVLGHJ9dSPSq4N0v8t4elX7k5ovKNAgMBAAECgf9gNRnFD4rF4eevR9OMgmIdkVgzj4w3Eqr7bh1viPU5fRSnpljvuN7L+zARs9VTKV2DTvDn+F5REA23SCR5g5jLQRGZcWy1PyBimEgkXDf6lO796QUyZ555UKp7samLbVBiLCaVYgPm8Z2U7pIwJibUtcsZBSrcEqGOzL8W9fzdyh36sFp64PZawJmbdc1SUAL7hVQr0QPGDGcuG/7PDB55Hpu5oH31xojsVUQlCR8Ll6ovUdl0XaQKsTM961vJKcYVDZ9WI762j9qB+y5HdwGW25T51PEGkBqge0/zYcxo/8ac7wb1iRl6G3hZt2BZwI52PZQlAuZn+PB6CQYTkr0CgYEA98TAAQxfzApcKjq/yBVw/0tsSNyBHKxflgIqpmQycgVPn/f0fEyR7e+9C+RtYZ/kyWTasQoHGieIP4QF/j0YI7N1LaMPn/bvb7WtPyH8Br6kCvSgypxe8V/XlFfqQVizbvan/H8w2/mF80zudouLJwWIexBC7jsoa6O2qFSmobsCgYEA4TN7iXrcN6tIK8mCDBo9PABIL8MgzzKLplj4nJlY3NxzeGOdl+atXytj5PDScuEqWRauz6G11WtLQnebOaaFIkEMi4wILpTWGjvyOzzDFJCfPu301PUvJfBwXoUbA314RQ18Vc+124nLVqVv6UYU+E9uXTnf4DVjSEx6n134NFcCgYEAlZgcWUWwXVBv/ytDebnAZNOUCJXh+n70o2yhdZ8PehpMzgf2fEn63c8etBxyEjxo9VPIWpX0Xc06jSbYO32FoqCKgkhueaWtQSRO+sw5D5VxFBBJOKubA19bmPxPuq6kf727BU+CH36TaqerXrW4CZJkqfDSiGX9bKgG87FQflsCgYAiIBYJSDfUq7zc/cUaJmO/Et/ddPkkzKkCxRqvSEGB/ln1FUtNOGRvNnkFuUR6qgorw9crmXqfY4ndAZjhDI3CGg9XmhmnTWCASzMyrMt2809eTtq55omFe0Db4dmtFrdB54A+1KHfKatJbvpdZARLeGXl9J4rMIvh6czvF2NEMwKBgQDyZG4maIHiwxO74MnvOemiLbBl78ixXLuNyZom4aI2sOxe2XpRwLOUihzjPY8FWazxU7CexhD/hH1Pr+NNQT8qjSJGKUBDNRFPbYLJ6XHjseK39F4p+6UAbd415cZ8GVRnUQcDMb6yV8c8mWqSlLAmcsB4Uet8ElcLVwVXF22odw==';
    // final rsaEncryptedFromjs =
    //     "ugpI/vwTw+5XN2VqZ1+VZCO31qJbg1s7mtsijoOH2TOyfpPUi+gD4Lc8543OHPSqyZB2D+WpOWOlVF+IWAoErNAwdHFGksBZdR3GymaF0oG6e2vjRh6dw/awI9GKlruCKrtYbqBrbpAS0Cufyp1Puo/uLSxSM5IM2zqtEWYOazTxWFRLn00FBuR1DPslXb1R2LErVhGLRYse2uHbs0kL8EhgRRDqU/4hYo9Yfw3W537l+Rv7SAEjVq3JDkydkW1QYehjG8B8cOZCTEXFCHljQGM0CZzZckf9nifxvMQfCaHA6A0ErJBIel2o7tZFVwW7jC3FnmoGIy5wYGSd0uWBlQ==";

    final rsaEncrypted =
        await rsaEncrypt(publicKey, Utf8Encoder().convert(originalText));
    final rsaDecrypted = await rsaDecrypt(privateKey, rsaEncrypted);
    expect(Utf8Decoder().convert(rsaDecrypted), originalText);
    // final rsaDecryptedJs = await rsaDecrypt(privateKey, rsaEncryptedFromjs);
    // expect(Utf8Decoder().convert(rsaDecryptedJs), originalText);
  });

  test('x25519 keys', () async {
    final ecPair1 = await generateExchangePair();
    final ecPair2 = await generateExchangePair();
    final derivedKey1 =
        await deriveExchangeSymKey(ecPair1.publicKey, ecPair2.privateKey);
    final derivedKey2 =
        await deriveExchangeSymKey(ecPair2.publicKey, ecPair1.privateKey);
    expect(derivedKey1, derivedKey2);
    final encrypted =
        await symEncrypt(derivedKey1, Utf8Encoder().convert(originalText));
    final decrypted = await symDecrypt(derivedKey2, encrypted);
    expect(Utf8Decoder().convert(decrypted), originalText);
  });
}
