package com.secureburn.chat

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.secureburn.chat.crypto.IdentityKeyStore
import com.secureburn.chat.crypto.MessageCrypto
import com.secureburn.chat.network.SecureBurnApi
import com.secureburn.chat.network.SecureBurnSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.KeyPair

class MainActivity : ComponentActivity() {
    private val identityStore = IdentityKeyStore()
    private val crypto = MessageCrypto()
    private val api = SecureBurnApi(BuildConfig.SERVER_BASE_URL)
    private var socket: SecureBurnSocket? = null
    private var keyPair: KeyPair? = null
    private var publicKey: JSONObject? = null
    private var friendPublicKey: JSONObject? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent { SecureBurnScreen() }
    }

    @Composable
    private fun SecureBurnScreen() {
        var userId by remember { mutableStateOf("") }
        var friendId by remember { mutableStateOf("") }
        var message by remember { mutableStateOf("") }
        var status by remember { mutableStateOf("未连接") }
        val messages = remember { mutableStateListOf<String>() }
        val scope = rememberCoroutineScope()

        MaterialTheme {
            Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Secure Burn Mobile", style = MaterialTheme.typography.headlineSmall)
                OutlinedTextField(userId, { userId = it }, label = { Text("你的 ID") }, modifier = Modifier.fillMaxWidth())
                Button(onClick = {
                    scope.launch(Dispatchers.IO) {
                        try {
                            keyPair = identityStore.loadOrCreate(userId)
                            publicKey = identityStore.publicJwk(keyPair!!)
                            api.register(userId, publicKey!!)
                            socket?.close()
                            socket = SecureBurnSocket(BuildConfig.SERVER_BASE_URL) { event ->
                                if (event.optString("type") == "message") {
                                    val friendKey = friendPublicKey ?: return@SecureBurnSocket
                                    val payload = crypto.decrypt(keyPair!!, friendKey, event.getJSONObject("encrypted"))
                                    runOnUiThread {
                                        messages.clear()
                                        messages.add("${event.getString("from")}: ${payload.getString("text")}")
                                    }
                                }
                                runOnUiThread { status = event.optString("type", "event") }
                            }
                            socket!!.connect(userId, publicKey!!)
                            runOnUiThread { status = "已登入，指纹 ${identityStore.fingerprint(publicKey!!)}" }
                        } catch (error: Throwable) {
                            runOnUiThread { status = "登入失败：${error.message}" }
                        }
                    }
                }) { Text("登入") }

                Divider()

                OutlinedTextField(friendId, { friendId = it }, label = { Text("好友 ID") }, modifier = Modifier.fillMaxWidth())
                Button(onClick = {
                    scope.launch(Dispatchers.IO) {
                        try {
                            val friend = api.getUser(friendId)
                            friendPublicKey = friend.getJSONObject("publicKey")
                            api.addFriend(userId, friendId, friendPublicKey!!)
                            runOnUiThread { status = "已添加好友 $friendId，指纹 ${friend.getString("fingerprint")}" }
                        } catch (error: Throwable) {
                            runOnUiThread { status = "添加失败：${error.message}" }
                        }
                    }
                }) { Text("添加好友") }

                Divider()

                OutlinedTextField(message, { message = it }, label = { Text("消息") }, modifier = Modifier.fillMaxWidth())
                Button(onClick = {
                    val kp = keyPair ?: return@Button
                    val friendKey = friendPublicKey ?: return@Button
                    val payload = JSONObject().put("text", message).put("burnAfter", 900).put("sentAt", System.currentTimeMillis())
                    val encrypted = crypto.encrypt(kp, friendKey, payload)
                    socket?.send(JSONObject().put("type", "message").put("from", userId).put("to", friendId).put("encrypted", encrypted))
                    messages.clear()
                    messages.add("我: $message")
                    message = ""
                }) { Text("发送加密消息") }

                Text(status, style = MaterialTheme.typography.bodySmall)
                LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
                    items(messages) { Text(it, Modifier.padding(vertical = 6.dp)) }
                }
            }
        }
    }
}

