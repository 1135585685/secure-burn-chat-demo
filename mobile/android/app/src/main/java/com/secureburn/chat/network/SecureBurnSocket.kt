package com.secureburn.chat.network

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject

class SecureBurnSocket(
    private val baseUrl: String,
    private val onEvent: (JSONObject) -> Unit
) {
    private val client = OkHttpClient()
    private var socket: WebSocket? = null

    fun connect(userId: String, publicKey: JSONObject) {
        val wsUrl = baseUrl.replace("https://", "wss://").replace("http://", "ws://")
        val request = Request.Builder().url(wsUrl).build()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.send(JSONObject().put("type", "hello").put("userId", userId).put("publicKey", publicKey).toString())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                onEvent(JSONObject(text))
            }
        })
    }

    fun send(packet: JSONObject) {
        socket?.send(packet.toString())
    }

    fun close() {
        socket?.close(1000, "closed")
    }
}

