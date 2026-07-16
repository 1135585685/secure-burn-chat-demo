import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/secure_repository.dart';
import 'models.dart';

final selectedTabProvider = StateProvider<int>((ref) => 0);

final repositoryProvider = Provider<SecureRepository>((ref) {
  return SecureRepository(baseUrl: 'https://secure-burn-chat-demo.onrender.com');
});

final identityProvider = StateProvider<AnonymousIdentity?>((ref) => null);
final activeSessionProvider = StateProvider<SecureSession?>((ref) => null);
final messagesProvider = StateProvider<List<SecureMessage>>((ref) => const []);

final securityBannerProvider = Provider<String>((ref) {
  final identity = ref.watch(identityProvider);
  final session = ref.watch(activeSessionProvider);
  if (identity == null) return '未建立匿名身份';
  if (session == null) return '${identity.userId} · 等待安全会话';
  if (session.state == SessionState.active) return '临时安全会话 · 已启用';
  if (session.state == SessionState.destroyed) return '会话已销毁 · 本地无历史';
  return '会话状态同步中';
});
