import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/app_state.dart';
import '../../core/models.dart';

class SessionPage extends ConsumerStatefulWidget {
  const SessionPage({super.key});

  @override
  ConsumerState<SessionPage> createState() => _SessionPageState();
}

class _SessionPageState extends ConsumerState<SessionPage> {
  final _peerController = TextEditingController();
  int _duration = 1800;

  @override
  void dispose() {
    _peerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final identity = ref.watch(identityProvider);
    final session = ref.watch(activeSessionProvider);
    final repo = ref.watch(repositoryProvider);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          elevation: 0,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('临时安全会话', style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 8),
                const Text('短生命周期、零历史、会话结束后通过删除密钥实现不可恢复。'),
                const SizedBox(height: 16),
                if (session == null || session.state == SessionState.destroyed) ...[
                  TextField(
                    controller: _peerController,
                    decoration: const InputDecoration(
                      labelText: '对方匿名 ID',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  SegmentedButton<int>(
                    segments: const [
                      ButtonSegment(value: 1800, label: Text('30 分钟')),
                      ButtonSegment(value: 7200, label: Text('2 小时')),
                      ButtonSegment(value: 3600, label: Text('手动')),
                    ],
                    selected: {_duration},
                    onSelectionChanged: (value) => setState(() => _duration = value.first),
                  ),
                  const SizedBox(height: 16),
                  FilledButton.icon(
                    onPressed: identity == null
                        ? null
                        : () async {
                            final created = await repo.createSession(
                              identity: identity,
                              receiverId: _peerController.text.trim(),
                              durationSeconds: _duration,
                            );
                            final active = await repo.acceptSession(created);
                            ref.read(activeSessionProvider.notifier).state = active;
                            ref.read(selectedTabProvider.notifier).state = 2;
                          },
                    icon: const Icon(Icons.local_fire_department),
                    label: const Text('创建临时安全会话'),
                  ),
                ] else ...[
                  _SessionStatus(session: session),
                  const SizedBox(height: 16),
                  FilledButton.tonalIcon(
                    onPressed: session.state != SessionState.active
                        ? null
                        : () async {
                            ref.read(activeSessionProvider.notifier).state = session.copyWith(state: SessionState.destroying);
                            await repo.destroySession(session);
                            ref.read(messagesProvider.notifier).state = const [];
                            ref.read(activeSessionProvider.notifier).state = session.copyWith(state: SessionState.destroyed);
                          },
                    icon: const Icon(Icons.delete_forever),
                    label: const Text('立即销毁会话'),
                    style: FilledButton.styleFrom(foregroundColor: const Color(0xFF991B1B)),
                  ),
                ],
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _SessionStatus extends StatelessWidget {
  const _SessionStatus({required this.session});

  final SecureSession session;

  @override
  Widget build(BuildContext context) {
    final remaining = session.expireTime.difference(DateTime.now());
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SelectableText('Session ID\n${session.sessionId}'),
        const SizedBox(height: 8),
        Text('状态：${session.state.name.toUpperCase()}'),
        Text('对方：${session.peerId}'),
        Text('剩余时间：${remaining.inMinutes.clamp(0, 9999)} 分钟'),
      ],
    );
  }
}
