enum SessionState { created, active, destroying, destroyed }

class AnonymousIdentity {
  const AnonymousIdentity({
    required this.userId,
    required this.publicKey,
    required this.fingerprint,
  });

  final String userId;
  final String publicKey;
  final String fingerprint;
}

class SecureSession {
  const SecureSession({
    required this.sessionId,
    required this.peerId,
    required this.peerPublicKey,
    required this.state,
    required this.expireTime,
  });

  final String sessionId;
  final String peerId;
  final String peerPublicKey;
  final SessionState state;
  final DateTime expireTime;

  SecureSession copyWith({SessionState? state}) {
    return SecureSession(
      sessionId: sessionId,
      peerId: peerId,
      peerPublicKey: peerPublicKey,
      state: state ?? this.state,
      expireTime: expireTime,
    );
  }
}

class SecureMessage {
  const SecureMessage({
    required this.id,
    required this.sessionId,
    required this.ciphertext,
    required this.createdTime,
  });

  final String id;
  final String sessionId;
  final String ciphertext;
  final DateTime createdTime;
}
