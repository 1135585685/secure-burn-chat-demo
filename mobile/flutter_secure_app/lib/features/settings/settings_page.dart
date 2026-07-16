import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/app_state.dart';

class SettingsPage extends ConsumerWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          elevation: 0,
          child: Column(
            children: [
              const ListTile(
                leading: Icon(Icons.cloud_done),
                title: Text('服务器'),
                subtitle: Text('https://secure-burn-chat-demo.onrender.com'),
              ),
              const ListTile(
                leading: Icon(Icons.visibility_off),
                title: Text('通知预览'),
                subtitle: Text('默认隐藏消息内容'),
              ),
              const ListTile(
                leading: Icon(Icons.backup_outlined),
                title: Text('云备份'),
                subtitle: Text('临时安全会话禁止备份'),
              ),
              ListTile(
                leading: const Icon(Icons.logout),
                title: const Text('退出并清除本机会话状态'),
                onTap: () {
                  ref.read(activeSessionProvider.notifier).state = null;
                  ref.read(messagesProvider.notifier).state = const [];
                },
              ),
            ],
          ),
        ),
      ],
    );
  }
}
