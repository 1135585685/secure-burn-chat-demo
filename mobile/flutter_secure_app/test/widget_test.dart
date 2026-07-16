import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:high_security_anonymous_messenger/main.dart';

void main() {
  testWidgets('renders secure messenger shell', (tester) async {
    await tester.pumpWidget(const ProviderScope(child: SecureMessengerApp()));

    expect(find.text('隐语'), findsOneWidget);
    expect(find.text('会话'), findsOneWidget);
    expect(find.text('身份'), findsOneWidget);
    expect(find.text('通信'), findsOneWidget);
    expect(find.text('安全'), findsOneWidget);
    expect(find.text('设置'), findsOneWidget);
  });
}
