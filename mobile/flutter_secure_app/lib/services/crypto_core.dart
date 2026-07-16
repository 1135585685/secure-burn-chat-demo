import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class CryptoCore {
  CryptoCore();

  static const _storage = FlutterSecureStorage();
  final _algorithm = Chacha20.poly1305Aead();
  final _keyExchange = X25519();
  final _random = Random.secure();

  Future<String> currentPublicKey() async {
    final existing = await _storage.read(key: 'device_public_key');
    if (existing != null) return existing;
    final keyPair = await _keyExchange.newKeyPair();
    final privateBytes = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();
    final encodedPublic = base64UrlEncode(publicKey.bytes);
    await _storage.write(key: 'device_private_key', value: base64UrlEncode(privateBytes));
    await _storage.write(key: 'device_public_key', value: encodedPublic);
    return encodedPublic;
  }

  Future<String> encryptSessionText(String sessionId, String peerPublicKey, String plaintext) async {
    final secret = await _sessionSecret(sessionId, peerPublicKey);
    final nonce = _randomBytes(12);
    final box = await _algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: secret,
      nonce: nonce,
    );
    return jsonEncode({
      'version': 1,
      'algorithm': 'ChaCha20-Poly1305',
      'session_id': sessionId,
      'nonce': base64UrlEncode(nonce),
      'ciphertext': base64UrlEncode(box.cipherText),
      'mac': base64UrlEncode(box.mac.bytes),
    });
  }

  Future<String> decryptSessionText(String sessionId, String peerPublicKey, String sealedJson) async {
    final sealed = jsonDecode(sealedJson) as Map<String, dynamic>;
    final secret = await _sessionSecret(sessionId, peerPublicKey);
    final clear = await _algorithm.decrypt(
      SecretBox(
        base64Url.decode(sealed['ciphertext'] as String),
        nonce: base64Url.decode(sealed['nonce'] as String),
        mac: Mac(base64Url.decode(sealed['mac'] as String)),
      ),
      secretKey: secret,
    );
    return utf8.decode(clear);
  }

  String paddingBlock() {
    return base64UrlEncode(_randomBytes(64));
  }

  Future<void> destroySession(String sessionId) async {
    await _storage.delete(key: 'session_key:$sessionId');
  }

  Future<SecretKey> _sessionSecret(String sessionId, String peerPublicKey) async {
    final keyName = 'session_key:$sessionId';
    final existing = await _storage.read(key: keyName);
    if (existing != null) return SecretKey(base64Url.decode(existing));
    final privateEncoded = await _storage.read(key: 'device_private_key');
    if (privateEncoded == null) {
      await currentPublicKey();
    }
    final privateKey = base64Url.decode((await _storage.read(key: 'device_private_key'))!);
    final localKeyPair = SimpleKeyPairData(
      privateKey,
      publicKey: SimplePublicKey(base64Url.decode((await _storage.read(key: 'device_public_key'))!), type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
    final shared = await _keyExchange.sharedSecretKey(
      keyPair: localKeyPair,
      remotePublicKey: SimplePublicKey(base64Url.decode(peerPublicKey), type: KeyPairType.x25519),
    );
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
    final derived = await hkdf.deriveKey(
      secretKey: shared,
      nonce: utf8.encode(sessionId),
      info: utf8.encode('HighSecurityAnonymousMessenger/session-v1'),
    );
    final key = await derived.extractBytes();
    await _storage.write(key: keyName, value: base64UrlEncode(key));
    return SecretKey(key);
  }

  List<int> _randomBytes(int length) {
    return List<int>.generate(length, (_) => _random.nextInt(256));
  }
}
