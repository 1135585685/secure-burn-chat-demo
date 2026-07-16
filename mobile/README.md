# Secure Burn Mobile

This directory contains native mobile app starters for the Secure Burn protocol.

Security constraints:

- Do not use WebView as the production client.
- Private identity keys must stay in platform key storage.
- The server must not receive private keys.
- The server must not receive plaintext unless explicit test capture mode is enabled.
- Message encryption remains end-to-end. The current demo protocol is `demo-ecdh-v1`; replace it with Signal/libsignal before production use.

Projects:

- `android/`: Kotlin Android starter using Android Keystore, OkHttp WebSocket, and AES-GCM payloads.
- `harmony/`: HarmonyOS ArkTS starter structure using HUKS as the intended key storage layer.
- `shared/`: protocol notes and payload examples.

Required local tooling:

- Android: Android Studio with Android SDK installed.
- HarmonyOS: DevEco Studio with HarmonyOS SDK installed.

Current server default:

```text
https://secure-burn-chat-demo.onrender.com
```

For local development:

```text
http://10.0.2.2:8787
```

Android emulator uses `10.0.2.2` to reach your Mac localhost.

