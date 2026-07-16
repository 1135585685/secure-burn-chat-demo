# Secure Burn Mobile Protocol

## Current Demo Protocol

The current server expects:

- `POST /api/register`
- `GET /api/users/:id`
- `POST /api/friends`
- `DELETE /api/friends`
- WebSocket `hello`
- WebSocket `message`

Encrypted message body:

```json
{
  "version": 1,
  "alg": "ECDH-P256+AES-GCM",
  "protocol": "demo-ecdh-v1",
  "iv": "base64",
  "ciphertext": "base64"
}
```

The plaintext before encryption:

```json
{
  "text": "message",
  "burnAfter": 900,
  "sentAt": 1777800000000
}
```

## Production Upgrade Requirement

Replace `demo-ecdh-v1` with Signal Protocol/libsignal before real production.

Required production stores:

- identity key store
- signed pre-key store
- one-time pre-key store
- session store
- sender key store for groups

Do not implement the double ratchet manually.

