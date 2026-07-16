package com.secureburn.chat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.util.Base64
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.secureburn.chat.crypto.IdentityKeyStore
import com.secureburn.chat.crypto.MessageCrypto
import com.secureburn.chat.model.Friend
import com.secureburn.chat.network.SecureBurnApi
import com.secureburn.chat.network.SecureBurnSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPair
import java.util.UUID
import kotlin.math.max

class MainActivity : ComponentActivity() {
    private val identityStore = IdentityKeyStore()
    private val crypto = MessageCrypto()
    private val api = SecureBurnApi(BuildConfig.SERVER_BASE_URL)
    private lateinit var prefs: SharedPreferences
    private var socket: SecureBurnSocket? = null
    private var keyPair: KeyPair? = null
    private var publicKey: JSONObject? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences("secure-burn-mobile", MODE_PRIVATE)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent { SecureBurnApp() }
    }

    override fun onDestroy() {
        socket?.close()
        super.onDestroy()
    }

    @Composable
    private fun SecureBurnApp() {
        var userId by remember { mutableStateOf(prefs.getString("lastUserId", "") ?: "") }
        var activeUserId by remember { mutableStateOf("") }
        var friendId by remember { mutableStateOf("") }
        var friendInvite by remember { mutableStateOf("") }
        var message by remember { mutableStateOf("") }
        var inviteCode by remember { mutableStateOf("") }
        var status by remember { mutableStateOf("未连接") }
        var fingerprint by remember { mutableStateOf("未生成") }
        var connected by remember { mutableStateOf(false) }
        var activeFriendId by remember { mutableStateOf("") }
        var currentMessage by remember { mutableStateOf<VisibleMessage?>(null) }
        var countdownNow by remember { mutableStateOf(System.currentTimeMillis()) }
        var wipeConfirm by remember { mutableStateOf(false) }
        val friends = remember { mutableStateListOf<Friend>() }
        val scope = rememberCoroutineScope()
        val activeFriend = friends.firstOrNull { it.userId == activeFriendId }
        val canSend = connected && activeUserId.isNotBlank() && activeFriend?.confirmed == true && activeFriend.online

        LaunchedEffect(currentMessage?.id) {
            while (currentMessage != null) {
                countdownNow = System.currentTimeMillis()
                val expiresAt = currentMessage?.expiresAt ?: 0L
                if (expiresAt <= countdownNow) currentMessage = null
                delay(500)
            }
        }

        MaterialTheme(
            colorScheme = MaterialTheme.colorScheme.copy(
                primary = Color(0xFF0F766E),
                secondary = Color(0xFF475569),
                surface = Color(0xFFF8FAFC),
                background = Color(0xFFF1F5F9)
            )
        ) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    item {
                        HeaderCard(
                            userId = userId,
                            onUserIdChange = { userId = it },
                            activeUserId = activeUserId,
                            status = status,
                            fingerprint = fingerprint,
                            inviteCode = inviteCode,
                            onLogin = {
                                val clean = userId.trim()
                                if (!isValidUserId(clean)) {
                                    status = "ID 只能包含字母、数字、下划线和短横线，长度 3-32。"
                                    return@HeaderCard
                                }
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val pair = identityStore.loadOrCreate(clean)
                                        val jwk = identityStore.publicJwk(pair)
                                        keyPair = pair
                                        publicKey = jwk
                                        val fp = identityStore.fingerprint(jwk)
                                        val registerResult = api.register(clean, jwk)
                                        val restored = restoreFriends(clean)
                                        val serverFriends = parseFriends(registerResult.optJSONArray("friends"))
                                        val merged = mergeFriendLists(restored, serverFriends)
                                        socket?.close()
                                        socket = createSocket(
                                            clean,
                                            jwk,
                                            onReady = { ready ->
                                                connected = true
                                                status = "已连接 Render 服务：${ready.optString("userId", clean)}"
                                                replaceFriends(friends, parseFriends(ready.optJSONArray("friends")))
                                                saveFriends(clean, friends)
                                            },
                                            onFriends = { incoming ->
                                                replaceFriends(friends, incoming)
                                                saveFriends(clean, friends)
                                            },
                                            onStatus = { status = it },
                                            onMessage = { packet ->
                                                val from = packet.optString("from")
                                                val friend = friends.firstOrNull { it.userId == from }
                                                if (friend == null) {
                                                    status = "收到未知联系人密文：$from"
                                                    return@createSocket
                                                }
                                                try {
                                                    val payload = crypto.decrypt(pair, friend.publicKey, packet.getJSONObject("encrypted"))
                                                    activeFriendId = from
                                                    currentMessage = VisibleMessage(
                                                        id = UUID.randomUUID().toString(),
                                                        senderKey = from,
                                                        from = from,
                                                        text = payload.optString("text"),
                                                        mine = false,
                                                        status = "已解密",
                                                        expiresAt = System.currentTimeMillis() + payload.optLong("burnAfter", 900L) * 1000L
                                                    )
                                                    status = "收到来自 $from 的端到端加密消息"
                                                } catch (error: Throwable) {
                                                    status = "收到消息，但解密失败。"
                                                }
                                            },
                                            onClose = {
                                                connected = false
                                                markOffline(friends)
                                                status = it
                                            }
                                        )
                                        socket!!.connect(clean, jwk)
                                        runOnUiThread {
                                            activeUserId = clean
                                            fingerprint = fp
                                            inviteCode = makeInvite(clean, jwk, fp)
                                            replaceFriends(friends, merged)
                                            saveFriends(clean, friends)
                                            prefs.edit().putString("lastUserId", clean).apply()
                                            status = "正在连接 Render 服务..."
                                        }
                                    } catch (error: Throwable) {
                                        runOnUiThread { status = "登入失败：${error.message ?: "服务不可用"}" }
                                    }
                                }
                            },
                            onCopyInvite = {
                                copyText("Secure Burn 邀请码", inviteCode)
                                status = "邀请代码已复制。"
                            },
                            onLogout = {
                                socket?.close()
                                socket = null
                                keyPair = null
                                publicKey = null
                                connected = false
                                activeUserId = ""
                                inviteCode = ""
                                fingerprint = "未生成"
                                activeFriendId = ""
                                currentMessage = null
                                friends.clear()
                                status = "已退出，本机当前会话已清空。"
                            },
                            onWipe = { wipeConfirm = true }
                        )
                    }

                    item {
                        FriendManagerCard(
                            friendId = friendId,
                            friendInvite = friendInvite,
                            onFriendIdChange = { friendId = it },
                            onFriendInviteChange = { friendInvite = it },
                            onAddFriend = {
                                if (activeUserId.isBlank()) {
                                    status = "请先登入。"
                                    return@FriendManagerCard
                                }
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val friend = resolveFriend(friendId.trim(), friendInvite.trim())
                                        if (friend.userId == activeUserId) error("不能添加自己")
                                        val result = api.addFriend(activeUserId, friend.userId, friend.publicKey)
                                        val incoming = parseFriends(result.optJSONArray("friends"))
                                        runOnUiThread {
                                            replaceFriends(friends, incoming)
                                            saveFriends(activeUserId, friends)
                                            activeFriendId = friend.userId
                                            friendId = ""
                                            friendInvite = ""
                                            status = "已添加好友 ${friend.userId}，等待双向确认后可通信。"
                                        }
                                    } catch (error: Throwable) {
                                        runOnUiThread { status = "添加失败：请确认好友 ID 已进入过系统，或粘贴完整邀请代码。" }
                                    }
                                }
                            }
                        )
                    }

                    item {
                        FriendsCard(
                            friends = friends,
                            activeFriendId = activeFriendId,
                            onSelect = {
                                activeFriendId = it
                                currentMessage = null
                            },
                            onDelete = { id ->
                                if (activeUserId.isBlank()) return@FriendsCard
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val result = api.deleteFriend(activeUserId, id)
                                        val incoming = parseFriends(result.optJSONArray("friends"))
                                        runOnUiThread {
                                            replaceFriends(friends, incoming)
                                            saveFriends(activeUserId, friends)
                                            if (activeFriendId == id) activeFriendId = ""
                                            currentMessage = null
                                            status = "已删除好友：$id"
                                        }
                                    } catch (error: Throwable) {
                                        runOnUiThread { status = "删除好友失败：${error.message ?: "服务不可用"}" }
                                    }
                                }
                            }
                        )
                    }

                    item {
                        ChatCard(
                            friend = activeFriend,
                            canSend = canSend,
                            message = message,
                            onMessageChange = { message = it },
                            currentMessage = currentMessage,
                            countdownSeconds = currentMessage?.let { max(0, ((it.expiresAt - countdownNow) / 1000).toInt()) } ?: 0,
                            onSend = {
                                val text = message.trim()
                                val pair = keyPair
                                val friend = activeFriend
                                if (text.isBlank() || pair == null || friend == null) return@ChatCard
                                if (!canSend) {
                                    status = if (friend.confirmed) "好友离线，暂不可发送。" else "需要双方互相添加好友后才可发送。"
                                    return@ChatCard
                                }
                                try {
                                    val payload = JSONObject()
                                        .put("text", text)
                                        .put("burnAfter", 900)
                                        .put("sentAt", System.currentTimeMillis())
                                    val encrypted = crypto.encrypt(pair, friend.publicKey, payload)
                                    socket?.send(
                                        JSONObject()
                                            .put("type", "message")
                                            .put("from", activeUserId)
                                            .put("to", friend.userId)
                                            .put("encrypted", encrypted)
                                    )
                                    currentMessage = VisibleMessage(
                                        id = UUID.randomUUID().toString(),
                                        senderKey = "me",
                                        from = "我",
                                        text = text,
                                        mine = true,
                                        status = "已加密发送",
                                        expiresAt = System.currentTimeMillis() + 900_000L
                                    )
                                    message = ""
                                } catch (error: Throwable) {
                                    status = "加密失败，消息没有发送。"
                                }
                            }
                        )
                    }
                }

                if (wipeConfirm) {
                    AlertDialog(
                        onDismissRequest = { wipeConfirm = false },
                        title = { Text("删除所有记录") },
                        text = { Text("将删除本机身份密钥、好友缓存、当前消息，并请求服务端删除该用户资料和好友关系。此操作不可恢复。") },
                        confirmButton = {
                            TextButton(onClick = {
                                wipeConfirm = false
                                val targetUserId = activeUserId.ifBlank { userId.trim() }
                                if (targetUserId.isBlank()) return@TextButton
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        api.deleteUser(targetUserId)
                                    } catch (_: Throwable) {
                                    }
                                    identityStore.delete(targetUserId)
                                    prefs.edit()
                                        .remove("lastUserId")
                                        .remove(friendsKey(targetUserId))
                                        .apply()
                                    runOnUiThread {
                                        socket?.close()
                                        socket = null
                                        keyPair = null
                                        publicKey = null
                                        userId = ""
                                        activeUserId = ""
                                        friendId = ""
                                        friendInvite = ""
                                        message = ""
                                        inviteCode = ""
                                        fingerprint = "未生成"
                                        connected = false
                                        activeFriendId = ""
                                        currentMessage = null
                                        friends.clear()
                                        status = "所有本机记录已删除，并已请求服务端删除资料。"
                                    }
                                }
                            }) { Text("确认删除", color = Color(0xFFB91C1C)) }
                        },
                        dismissButton = { TextButton(onClick = { wipeConfirm = false }) { Text("取消") } }
                    )
                }
            }
        }
    }

    @Composable
    private fun HeaderCard(
        userId: String,
        onUserIdChange: (String) -> Unit,
        activeUserId: String,
        status: String,
        fingerprint: String,
        inviteCode: String,
        onLogin: () -> Unit,
        onCopyInvite: () -> Unit,
        onLogout: () -> Unit,
        onWipe: () -> Unit
    ) {
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column {
                    Text("Secure Burn", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text("Android 端到端加密客户端", color = Color(0xFF64748B))
                }
                StatusPill(if (activeUserId.isBlank()) "未登入" else "已登入", activeUserId.isNotBlank())
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = userId,
                onValueChange = onUserIdChange,
                label = { Text("你的 ID") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onLogin, modifier = Modifier.weight(1f)) { Text("登入") }
                OutlinedButton(onClick = onLogout, enabled = activeUserId.isNotBlank()) { Text("退出") }
            }
            Spacer(Modifier.height(10.dp))
            Text(status, color = Color(0xFF334155), style = MaterialTheme.typography.bodyMedium)
            Text("身份指纹：$fingerprint", color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
            if (inviteCode.isNotBlank()) {
                Spacer(Modifier.height(10.dp))
                Text("邀请代码", fontWeight = FontWeight.SemiBold)
                Text(inviteCode, maxLines = 2, overflow = TextOverflow.Ellipsis, color = Color(0xFF475569))
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onCopyInvite, modifier = Modifier.weight(1f)) { Text("复制邀请代码") }
                    OutlinedButton(
                        onClick = onWipe,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFB91C1C))
                    ) { Text("删除所有记录") }
                }
            }
        }
    }

    @Composable
    private fun FriendManagerCard(
        friendId: String,
        friendInvite: String,
        onFriendIdChange: (String) -> Unit,
        onFriendInviteChange: (String) -> Unit,
        onAddFriend: () -> Unit
    ) {
        SectionCard {
            Text("添加好友", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = friendId,
                onValueChange = onFriendIdChange,
                label = { Text("好友 ID") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = friendInvite,
                onValueChange = onFriendInviteChange,
                label = { Text("或粘贴完整邀请代码") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            Button(onClick = onAddFriend, modifier = Modifier.fillMaxWidth()) { Text("添加好友") }
        }
    }

    @Composable
    private fun FriendsCard(
        friends: List<Friend>,
        activeFriendId: String,
        onSelect: (String) -> Unit,
        onDelete: (String) -> Unit
    ) {
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("好友", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text("${friends.size} 位", color = Color(0xFF64748B))
            }
            Spacer(Modifier.height(8.dp))
            if (friends.isEmpty()) {
                Text("暂无好友。用 ID 或邀请代码添加联系人。", color = Color(0xFF64748B))
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    friends.forEach { friend ->
                        FriendRow(
                            friend = friend,
                            selected = friend.userId == activeFriendId,
                            onSelect = { onSelect(friend.userId) },
                            onDelete = { onDelete(friend.userId) }
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun FriendRow(friend: Friend, selected: Boolean, onSelect: () -> Unit, onDelete: () -> Unit) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, if (selected) Color(0xFF0F766E) else Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                .background(if (selected) Color(0xFFE6FFFA) else Color.White, RoundedCornerShape(10.dp))
                .clickable(onClick = onSelect)
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .background(if (friend.online) Color(0xFF16A34A) else if (friend.confirmed) Color(0xFF94A3B8) else Color(0xFFF59E0B), CircleShape)
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(friend.userId, fontWeight = FontWeight.SemiBold)
                Text(friendState(friend), color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
                Text(friend.fingerprint, maxLines = 1, overflow = TextOverflow.Ellipsis, color = Color(0xFF94A3B8), style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onDelete) { Text("删除", color = Color(0xFFB91C1C)) }
        }
    }

    @Composable
    private fun ChatCard(
        friend: Friend?,
        canSend: Boolean,
        message: String,
        onMessageChange: (String) -> Unit,
        currentMessage: VisibleMessage?,
        countdownSeconds: Int,
        onSend: () -> Unit
    ) {
        SectionCard {
            Text(friend?.userId ?: "请选择好友", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(chatSubtitle(friend), color = Color(0xFF64748B))
            Spacer(Modifier.height(12.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(150.dp)
                    .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(12.dp))
                    .background(Color(0xFFF8FAFC), RoundedCornerShape(12.dp))
                    .padding(14.dp)
            ) {
                if (currentMessage == null) {
                    Text("单消息窗口为空。本机不保留聊天记录。", color = Color(0xFF94A3B8), modifier = Modifier.align(Alignment.Center))
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("${currentMessage.from} · ${currentMessage.status}", color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
                        Text(currentMessage.text, style = MaterialTheme.typography.bodyLarge)
                        Text("${formatCountdown(countdownSeconds)} 后消失", color = Color(0xFFB45309), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = message,
                onValueChange = onMessageChange,
                label = { Text("加密消息") },
                minLines = 2,
                enabled = friend != null,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            Button(onClick = onSend, enabled = canSend, modifier = Modifier.fillMaxWidth()) { Text("发送端到端加密消息") }
        }
    }

    @Composable
    private fun SectionCard(content: @Composable ColumnScope.() -> Unit) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
        ) {
            Column(Modifier.fillMaxWidth().padding(14.dp), content = content)
        }
    }

    @Composable
    private fun StatusPill(text: String, active: Boolean) {
        Text(
            text = text,
            color = if (active) Color(0xFF065F46) else Color(0xFF475569),
            modifier = Modifier
                .background(if (active) Color(0xFFD1FAE5) else Color(0xFFE2E8F0), RoundedCornerShape(999.dp))
                .padding(horizontal = 10.dp, vertical = 5.dp)
        )
    }

    private fun createSocket(
        userId: String,
        jwk: JSONObject,
        onReady: (JSONObject) -> Unit,
        onFriends: (List<Friend>) -> Unit,
        onStatus: (String) -> Unit,
        onMessage: (JSONObject) -> Unit,
        onClose: (String) -> Unit
    ): SecureBurnSocket {
        return SecureBurnSocket(BuildConfig.SERVER_BASE_URL) { event ->
            runOnUiThread {
                when (event.optString("type")) {
                    "ready" -> onReady(event)
                    "friends" -> onFriends(parseFriends(event.optJSONArray("friends")))
                    "message" -> onMessage(event)
                    "sent" -> onStatus(if (event.optString("delivery") == "delivered") "密文已送达：${event.optString("to")}" else "密文已进入短期队列。")
                    "delivered" -> onStatus("密文已送达：${event.optString("to")}")
                    "expired" -> onStatus("密文未送达并已过期。")
                    "keyChanged" -> {
                        onFriends(parseFriends(event.optJSONArray("friends")))
                        onStatus("${event.optString("userId")} 的身份密钥发生变化，请重新核对指纹。")
                    }
                    "accountDeleted" -> onClose("账号记录已删除。")
                    "error" -> onStatus(event.optString("message", "服务端返回错误。"))
                    "closed" -> onClose("连接已断开。")
                    "socketError" -> onClose("连接失败：${event.optString("message")}")
                }
            }
        }
    }

    private fun resolveFriend(rawId: String, rawInvite: String): Friend {
        if (rawInvite.isNotBlank()) {
            val parsed = parseInvite(rawInvite)
            return Friend(
                userId = parsed.getString("userId"),
                publicKey = parsed.getJSONObject("publicKey"),
                fingerprint = parsed.optString("fingerprint", identityStore.fingerprint(parsed.getJSONObject("publicKey"))),
                confirmed = false,
                online = false
            )
        }
        if (!isValidUserId(rawId)) error("bad id")
        val result = api.getUser(rawId)
        return Friend(
            userId = result.getString("userId"),
            publicKey = result.getJSONObject("publicKey"),
            fingerprint = result.optString("fingerprint", identityStore.fingerprint(result.getJSONObject("publicKey"))),
            confirmed = false,
            online = false
        )
    }

    private fun parseFriends(array: JSONArray?): List<Friend> {
        if (array == null) return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val publicKey = item.optJSONObject("publicKey") ?: return@mapNotNull null
            Friend(
                userId = item.optString("userId"),
                publicKey = publicKey,
                fingerprint = item.optString("fingerprint", identityStore.fingerprint(publicKey)),
                confirmed = item.optBoolean("confirmed"),
                online = item.optBoolean("online")
            )
        }.filter { it.userId.isNotBlank() }
    }

    private fun replaceFriends(target: MutableList<Friend>, incoming: List<Friend>) {
        target.clear()
        target.addAll(incoming.sortedBy { it.userId })
    }

    private fun mergeFriendLists(local: List<Friend>, remote: List<Friend>): List<Friend> {
        val merged = local.associateBy { it.userId }.toMutableMap()
        for (friend in remote) merged[friend.userId] = friend
        return merged.values.sortedBy { it.userId }
    }

    private fun markOffline(target: MutableList<Friend>) {
        val copy = target.map { it.copy(online = false) }
        target.clear()
        target.addAll(copy)
    }

    private fun saveFriends(userId: String, friends: List<Friend>) {
        val array = JSONArray()
        for (friend in friends) {
            array.put(
                JSONObject()
                    .put("userId", friend.userId)
                    .put("publicKey", friend.publicKey)
                    .put("fingerprint", friend.fingerprint)
                    .put("confirmed", friend.confirmed)
                    .put("online", false)
            )
        }
        prefs.edit().putString(friendsKey(userId), array.toString()).apply()
    }

    private fun restoreFriends(userId: String): List<Friend> {
        return try {
            parseFriends(JSONArray(prefs.getString(friendsKey(userId), "[]")))
        } catch (_: Throwable) {
            emptyList()
        }
    }

    private fun friendsKey(userId: String) = "friends:$userId"

    private fun makeInvite(userId: String, key: JSONObject, fingerprint: String): String {
        val payload = JSONObject().put("userId", userId).put("publicKey", key).put("fingerprint", fingerprint)
        return Base64.encodeToString(payload.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    private fun parseInvite(value: String): JSONObject {
        return JSONObject(String(Base64.decode(value, Base64.DEFAULT), Charsets.UTF_8))
    }

    private fun copyText(label: String, value: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
    }

    private fun isValidUserId(value: String): Boolean = Regex("^[a-zA-Z0-9_-]{3,32}$").matches(value)

    private fun friendState(friend: Friend): String {
        if (!friend.confirmed) return "待对方确认"
        return if (friend.online) "在线，可发送" else "离线"
    }

    private fun chatSubtitle(friend: Friend?): String {
        if (friend == null) return "双方互相添加且在线后才可发送。"
        if (!friend.confirmed) return "等待对方也添加你，完成双向确认。"
        if (!friend.online) return "好友离线，暂不可发送。"
        return "双向确认且在线，可发送端到端加密消息。"
    }

    private fun formatCountdown(totalSeconds: Int): String {
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return "$minutes:${seconds.toString().padStart(2, '0')}"
    }

    private data class VisibleMessage(
        val id: String,
        val senderKey: String,
        val from: String,
        val text: String,
        val mine: Boolean,
        val status: String,
        val expiresAt: Long
    )
}
