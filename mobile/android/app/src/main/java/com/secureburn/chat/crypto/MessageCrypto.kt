package com.secureburn.chat.crypto

import android.util.Base64
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECGenParameterSpec
import java.security.AlgorithmParameters
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import java.security.MessageDigest

class MessageCrypto {
    fun encrypt(keyPair: KeyPair, friendPublicJwk: JSONObject, plaintext: JSONObject): JSONObject {
        val secret = deriveSharedSecret(keyPair, friendPublicJwk)
        val aesKey = MessageDigest.getInstance("SHA-256").digest(secret)
        val iv = Random.Default.nextBytes(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext.toString().toByteArray(Charsets.UTF_8))
        return JSONObject()
            .put("version", 1)
            .put("alg", "ECDH-P256+AES-GCM")
            .put("protocol", "demo-ecdh-v1")
            .put("iv", b64(iv))
            .put("ciphertext", b64(ciphertext))
    }

    fun decrypt(keyPair: KeyPair, friendPublicJwk: JSONObject, encrypted: JSONObject): JSONObject {
        val secret = deriveSharedSecret(keyPair, friendPublicJwk)
        val aesKey = MessageDigest.getInstance("SHA-256").digest(secret)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(aesKey, "AES"),
            GCMParameterSpec(128, fromB64(encrypted.getString("iv")))
        )
        val plaintext = cipher.doFinal(fromB64(encrypted.getString("ciphertext")))
        return JSONObject(String(plaintext, Charsets.UTF_8))
    }

    private fun deriveSharedSecret(keyPair: KeyPair, friendPublicJwk: JSONObject): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(keyPair.private)
        agreement.doPhase(importPublicKey(friendPublicJwk), true)
        return agreement.generateSecret()
    }

    private fun importPublicKey(jwk: JSONObject): PublicKey {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val ecSpec = params.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        val point = ECPoint(BigInteger(1, fromB64(jwk.getString("x"))), BigInteger(1, fromB64(jwk.getString("y"))))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, ecSpec))
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun fromB64(value: String): ByteArray =
        Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}

