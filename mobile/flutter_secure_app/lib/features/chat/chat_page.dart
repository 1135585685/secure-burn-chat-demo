import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/app_state.dart';
import '../../core/models.dart';

class ChatPage extends ConsumerStatefulWidget {
  const ChatPage({super.key});

  @override
  ConsumerState<ChatPage> createState() => _ChatPageState();
}

class _ChatPageState extends ConsumerState<ChatPage> {
  final _messageController = TextEditingController();

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final identity = ref.watch(identityProvider);
    final session = ref.watch(activeSessionProvider);
    final messages = ref.watch(messagesProvider);
    final repo = ref.watch(repositoryProvider);
    final canSend = identity != null && session != null && session.state == SessionState.active;
    return Column(
      children: [
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(16),
          color: Colors.white,
          child: Text(session == null ? '没有活动会话' : '${session.peerId} · 临时安全会话'),
        ),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (messages.isEmpty)
                const Center(child: Text('单会话窗口为空。本机不保留历史消息。')),
              for (final message in messages)
                Card(
                  elevation: 0,
                  child: ListTile(
                    leading: const Icon(Icons.lock),
                    title: Text('密文 ${message.id}'),
                    subtitle: Text(message.ciphertext, maxLines: 2, overflow: TextOverflow.ellipsis),
                  ),
                ),
            ],
          ),
        ),
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    enabled: canSend,
                    decoration: const InputDecoration(
                      hintText: '输入端到端加密消息',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  onPressed: !canSend
                      ? null
                      : () async {
                          final text = _messageController.text.trim();
                          if (text.isEmpty) return;
                          await repo.sendMessage(identity: identity, session: session, plaintext: text);
                          _messageController.clear();
                          final pulled = await repo.pullMessages(identity: identity, session: session);
                          ref.read(messagesProvider.notifier).state = pulled;
                        },
                  icon: const Icon(Icons.send),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
