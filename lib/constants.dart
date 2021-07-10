const ITERATIONS = 10000;
const HASH_LENGTH = 256;

class EcPair {
  final String publicKey;
  final String privateKey;
  EcPair(this.publicKey, this.privateKey);
}
