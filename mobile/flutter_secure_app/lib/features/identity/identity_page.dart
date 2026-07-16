import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/app_state.dart';

class IdentityPage extends ConsumerWidget {
  const IdentityPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final identity = ref.watch(identityProvider);
    final repo = ref.watch(repositoryProvider);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _Panel(
          title: '匿名身份',
          child: identity == null
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('本应用不使用手机号、邮箱或真实姓名。身份由设备本地密钥生成，服务器只保存公钥。'),
                    const SizedBox(height: 16),
                    FilledButton.icon(
                      onPressed: () async {
                        final created = await repo.createIdentity();
                        ref.read(identityProvider.notifier).state = created;
                      },
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('创建匿名身份'),
                    ),
                  ],
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SelectableText('用户 ID\n${identity.userId}'),
                    const SizedBox(height: 12),
                    SelectableText('身份指纹\n${identity.fingerprint}'),
                    const SizedBox(height: 12),
                    Text('设备公钥已注册', style: Theme.of(context).textTheme.bodyMedium),
                  ],
                ),
        ),
      ],
    );
  }
}

class _Panel extends StatelessWidget {
  const _Panel({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}
