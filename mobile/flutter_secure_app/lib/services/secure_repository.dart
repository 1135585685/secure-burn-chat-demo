import 'dart:convert';

import 'package:http/http.dart' as http;

import '../core/models.dart';
import 'crypto_core.dart';

class SecureRepository {
  SecureRepository({required this.baseUrl});

  final String baseUrl;
  final CryptoCore crypto = CryptoCore();

  Future<AnonymousIdentity> createIdentity() async {
    final key = await crypto.currentPublicKey();
    final response = await _post('/api/v1/identity/create', {
      'device_public_key': key,
      'device_type': 'FLUTTER',
    });
    final identity = AnonymousIdentity(
      userId: response['user_id'] as String,
      publicKey: key,
      fingerprint: response['fingerprint'] as String,
    );
    await registerDevice(identity);
    return identity;
  }

  Future<void> registerDevice(AnonymousIdentity identity) async {
    await _post('/api/v1/device/register', {
      'user_id': identity.userId,
      'device_key': identity.publicKey,
      'device_type': 'FLUTTER',
    });
  }

  Future<SecureSession> createSession({
    required AnonymousIdentity identity,
    required String receiverId,
    int durationSeconds = 1800,
  }) async {
    final receiver = await getIdentity(receiverId);
    final response = await _post('/api/v1/session/create', {
      'creator_id': identity.userId,
      'receiver_id': receiverId,
      'mode': 'EPHEMERAL_SESSION',
      'duration': durationSeconds,
      'encrypted_metadata': {
        'client': 'flutter',
        'policy': 'SESSION_END',
      },
    });
    return SecureSession(
      sessionId: response['session_id'] as String,
      peerId: receiverId,
      peerPublicKey: receiver.publicKey,
      state: SessionState.created,
      expireTime: DateTime.fromMillisecondsSinceEpoch(response['expire_time'] as int),
    );
  }

  Future<AnonymousIdentity> getIdentity(String userId) async {
    final response = await http.get(Uri.parse('$baseUrl/api/v1/identity/$userId'));
    if (response.statusCode >= 400) throw StateError(response.body);
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    return AnonymousIdentity(
      userId: body['user_id'] as String,
      publicKey: body['public_key'] is String ? body['public_key'] as String : jsonEncode(body['public_key']),
      fingerprint: body['fingerprint'] as String,
    );
  }

  Future<SecureSession> acceptSession(SecureSession session) async {
    final response = await _post('/api/v1/session/accept', {
      'session_id': session.sessionId,
      'device_key': await crypto.currentPublicKey(),
    });
    if (response['status'] != 'ACTIVE') {
      throw StateError('Session was not activated');
    }
    return session.copyWith(state: SessionState.active);
  }

  Future<void> destroySession(SecureSession session) async {
    await _post('/api/v1/session/destroy', {
      'session_id': session.sessionId,
      'reason': 'client_destroy',
    });
    await crypto.destroySession(session.sessionId);
  }

  Future<void> sendMessage({
    required AnonymousIdentity identity,
    required SecureSession session,
    required String plaintext,
  }) async {
    final ciphertext = await crypto.encryptSessionText(session.sessionId, session.peerPublicKey, plaintext);
    await _post('/api/v1/message/send', {
      'session_id': session.sessionId,
      'sender_id': identity.userId,
      'recipient_id': session.peerId,
      'message_type': 'TEXT',
      'ciphertext': ciphertext,
      'padding': crypto.paddingBlock(),
    });
  }

  Future<List<SecureMessage>> pullMessages({
    required AnonymousIdentity identity,
    required SecureSession session,
  }) async {
    final uri = Uri.parse('$baseUrl/api/v1/message/pull').replace(queryParameters: {
      'user_id': identity.userId,
      'session_id': session.sessionId,
    });
    final response = await http.get(uri);
    if (response.statusCode >= 400) throw StateError(response.body);
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final messages = (body['messages'] as List<dynamic>? ?? const [])
        .map((item) {
          final map = item as Map<String, dynamic>;
          return SecureMessage(
            id: map['id'] as String,
            sessionId: map['session_id'] as String,
            ciphertext: map['ciphertext'] as String,
            createdTime: DateTime.fromMillisecondsSinceEpoch(map['created_time'] as int),
          );
        })
        .toList();
    return messages;
  }

  Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body) async {
    final response = await http.post(
      Uri.parse('$baseUrl$path'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode >= 400) throw StateError(response.body);
    return jsonDecode(response.body) as Map<String, dynamic>;
  }
}
