package com.secureburn.chat.network

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class SecureBurnApi(private val baseUrl: String) {
    private val client = OkHttpClient()
    private val jsonType = "application/json; charset=utf-8".toMediaType()

    fun register(userId: String, publicKey: JSONObject): JSONObject {
        return post("/api/register", JSONObject().put("userId", userId).put("publicKey", publicKey))
    }

    fun addFriend(userId: String, friendId: String, publicKey: JSONObject): JSONObject {
        val friend = JSONObject().put("userId", friendId).put("publicKey", publicKey)
        return post("/api/friends", JSONObject().put("userId", userId).put("friend", friend))
    }

    fun getUser(userId: String): JSONObject {
        val request = Request.Builder().url("$baseUrl/api/users/$userId").get().build()
        client.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) error(body)
            return JSONObject(body)
        }
    }

    private fun post(path: String, body: JSONObject): JSONObject {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .post(body.toString().toRequestBody(jsonType))
            .build()
        client.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) error(text)
            return JSONObject(text)
        }
    }
}

