package com.secureburn.chat.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class IdentityKeyStore {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun loadOrCreate(userId: String): KeyPair {
        val alias = alias(userId)
        if (!keyStore.containsAlias(alias)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        val privateKey = keyStore.getKey(alias, null) as java.security.PrivateKey
        val publicKey = keyStore.getCertificate(alias).publicKey
        return KeyPair(publicKey, privateKey)
    }

    fun delete(userId: String) {
        keyStore.deleteEntry(alias(userId))
    }

    fun publicJwk(keyPair: KeyPair): JSONObject {
        val ec = keyPair.public as ECPublicKey
        val size = 32
        return JSONObject()
            .put("kty", "EC")
            .put("crv", "P-256")
            .put("x", base64Url(unsigned(ec.w.affineX.toByteArray(), size)))
            .put("y", base64Url(unsigned(ec.w.affineY.toByteArray(), size)))
            .put("ext", true)
            .put("key_ops", org.json.JSONArray())
    }

    fun fingerprint(publicJwk: JSONObject): String {
        val canonical = canonicalJson(publicJwk)
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
            .chunked(4)
            .take(8)
            .joinToString(" ")
    }

    private fun alias(userId: String) = "secure-burn-identity-$userId"

    private fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun unsigned(bytes: ByteArray, size: Int): ByteArray {
        val clean = bytes.dropWhile { it == 0.toByte() }.toByteArray()
        return if (clean.size >= size) clean.takeLast(size).toByteArray()
        else ByteArray(size - clean.size) + clean
    }

    private fun canonicalJson(value: Any?): String = when (value) {
        is JSONObject -> value.keys().asSequence().toList().sorted()
            .joinToString(prefix = "{", postfix = "}") { key -> "\"$key\":${canonicalJson(value.get(key))}" }
        is org.json.JSONArray -> (0 until value.length()).joinToString(prefix = "[", postfix = "]") { canonicalJson(value.get(it)) }
        is String -> JSONObject.quote(value)
        else -> value.toString()
    }
}

