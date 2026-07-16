# Secure Burn Mobile

This directory now contains the migration from the original demo app to the v3.0 product architecture.

Primary client:

- `flutter_secure_app/`: replacement Flutter app for the High Security Anonymous E2EE Messaging Platform v3.0 architecture.

Compatibility prototypes:

- `android/`: previous Kotlin Android prototype. Kept for reference and APK continuity.
- `harmony/`: HarmonyOS starter structure.
- `shared/`: legacy protocol notes.

Target architecture:

- Flutter UI
- Riverpod state management
- Repository pattern
- Rust crypto core skeleton
- Anonymous identity
- Device registration
- Ephemeral secure sessions
- Session-based destruction
- Blind server message relay

Current server default:

```text
https://secure-burn-chat-demo.onrender.com
```

Build the replacement Flutter app:

```bash
cd mobile/flutter_secure_app
flutter pub get
flutter build apk --debug
```

Security note:

The current replacement client implements the target app and API flow, but production security still requires completing Rust FFI integration, independent audit, hardened multi-device key registration, and platform release builds.
