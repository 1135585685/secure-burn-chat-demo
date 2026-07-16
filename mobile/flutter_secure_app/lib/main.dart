import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/app_state.dart';
import 'features/chat/chat_page.dart';
import 'features/identity/identity_page.dart';
import 'features/security/security_page.dart';
import 'features/session/session_page.dart';
import 'features/settings/settings_page.dart';

void main() {
  runApp(const ProviderScope(child: SecureMessengerApp()));
}

class SecureMessengerApp extends ConsumerWidget {
  const SecureMessengerApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: '隐语',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF0F766E),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF6F7F9),
        useMaterial3: true,
      ),
      home: const AppShell(),
    );
  }
}

class AppShell extends ConsumerWidget {
  const AppShell({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final tab = ref.watch(selectedTabProvider);
    final pages = const [
      SessionPage(),
      IdentityPage(),
      ChatPage(),
      SecurityPage(),
      SettingsPage(),
    ];
    return Scaffold(
      appBar: AppBar(
        title: const Text('隐语'),
        centerTitle: false,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 16),
            child: Center(child: Text(ref.watch(securityBannerProvider))),
          ),
        ],
      ),
      body: pages[tab],
      bottomNavigationBar: NavigationBar(
        selectedIndex: tab,
        onDestinationSelected: (index) => ref.read(selectedTabProvider.notifier).state = index,
        destinations: const [
          NavigationDestination(icon: Icon(Icons.local_fire_department_outlined), selectedIcon: Icon(Icons.local_fire_department), label: '会话'),
          NavigationDestination(icon: Icon(Icons.fingerprint), label: '身份'),
          NavigationDestination(icon: Icon(Icons.lock_outline), selectedIcon: Icon(Icons.lock), label: '通信'),
          NavigationDestination(icon: Icon(Icons.security), label: '安全'),
          NavigationDestination(icon: Icon(Icons.settings_outlined), selectedIcon: Icon(Icons.settings), label: '设置'),
        ],
      ),
    );
  }
}
