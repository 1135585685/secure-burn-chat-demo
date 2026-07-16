# High Security Anonymous Messenger v3.0

This Flutter client replaces the original Android-only prototype as the target app architecture.

Implemented scope:

- Anonymous identity creation through `/api/v1/identity/create`
- Device registration through `/api/v1/device/register`
- Ephemeral secure session lifecycle through `/api/v1/session/*`
- Blind encrypted message queue through `/api/v1/message/*`
- Session-based destruction mode
- Riverpod state model and repository layer
- Rust crypto core skeleton under `rust/crypto_core`

Security note:

The server is blind to plaintext. The app encrypts before upload and destroys local session material when a session is terminated. The Rust FFI module is scaffolded for production hardening; the Flutter MVP currently uses Dart cryptography primitives until Flutter/Rust toolchains are available locally.

Build after Flutter SDK is installed:

```bash
cd mobile/flutter_secure_app
flutter pub get
flutter build apk --debug
```
