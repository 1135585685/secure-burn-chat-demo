package com.secureburn.chat.model

import org.json.JSONObject

data class Friend(
    val userId: String,
    val publicKey: JSONObject,
    val fingerprint: String,
    val confirmed: Boolean,
    val online: Boolean
)

