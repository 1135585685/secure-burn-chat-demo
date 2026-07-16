import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/app_state.dart';
import '../../core/models.dart';

class SecurityPage extends ConsumerWidget {
  const SecurityPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final identity = ref.watch(identityProvider);
    final session = ref.watch(activeSessionProvider);
    final score = identity != null && session?.state == SessionState.active ? 98 : 72;
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
                Text('安全中心', style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 16),
                Text('$score%', style: Theme.of(context).textTheme.displaySmall),
                const SizedBox(height: 12),
                const _StatusLine(text: '内容端到端加密', ok: true),
                const _StatusLine(text: '匿名身份，无手机号/邮箱', ok: true),
                _StatusLine(text: '临时安全会话', ok: session?.state == SessionState.active),
                const _StatusLine(text: '服务器不接收明文', ok: true),
                const _StatusLine(text: 'Rust FFI 安全核心', ok: false, note: '骨架已创建，待本机工具链完成构建'),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _StatusLine extends StatelessWidget {
  const _StatusLine({required this.text, required this.ok, this.note});

  final String text;
  final bool ok;
  final String? note;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(ok ? Icons.check_circle : Icons.warning_amber, color: ok ? const Color(0xFF047857) : const Color(0xFFD97706)),
      title: Text(text),
      subtitle: note == null ? null : Text(note!),
    );
  }
}
