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
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
        var statusTone by remember { mutableStateOf(UiTone.INFO) }
        var fingerprint by remember { mutableStateOf("未生成") }
        var connected by remember { mutableStateOf(false) }
        var activeFriendId by remember { mutableStateOf("") }
        var currentMessage by remember { mutableStateOf<VisibleMessage?>(null) }
        var countdownNow by remember { mutableStateOf(System.currentTimeMillis()) }
        var wipeConfirm by remember { mutableStateOf(false) }
        var addFriendDialog by remember { mutableStateOf(false) }
        var selectedTab by remember { mutableStateOf(AppTab.CHATS) }
        val friends = remember { mutableStateListOf<Friend>() }
        val keyChangedFriends = remember { mutableStateListOf<String>() }
        val scope = rememberCoroutineScope()
        val activeFriend = friends.firstOrNull { it.userId == activeFriendId }
        val activeKeyChanged = activeFriendId in keyChangedFriends
        val canSend = connected && activeUserId.isNotBlank() && activeFriend?.confirmed == true && !activeKeyChanged

        LaunchedEffect(currentMessage?.id) {
            while (currentMessage != null) {
                countdownNow = System.currentTimeMillis()
                val expiresAt = currentMessage?.expiresAt ?: 0L
                if (expiresAt <= countdownNow) {
                    currentMessage = null
                    status = "最后一条消息已超过 15 分钟并从本机清除。"
                    statusTone = UiTone.WARNING
                }
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
            Scaffold(
                containerColor = MaterialTheme.colorScheme.background,
                bottomBar = {
                    BottomNavigationBar(selectedTab = selectedTab, onSelect = { selectedTab = it })
                }
            ) { innerPadding ->
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(horizontal = 16.dp, vertical = 12.dp),
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
                                                statusTone = UiTone.SUCCESS
                                                replaceFriends(friends, parseFriends(ready.optJSONArray("friends")), keyChangedFriends)
                                                saveFriends(clean, friends)
                                            },
                                            onFriends = { incoming ->
                                                replaceFriends(friends, incoming, keyChangedFriends)
                                                saveFriends(clean, friends)
                                            },
                                            onStatus = { text, tone ->
                                                status = text
                                                statusTone = tone
                                            },
                                            onMessage = { packet ->
                                                val from = packet.optString("from")
                                                val friend = friends.firstOrNull { it.userId == from }
                                                if (friend == null) {
                                                    status = "收到未知联系人密文：$from"
                                                    statusTone = UiTone.WARNING
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
                                                    statusTone = UiTone.SUCCESS
                                                } catch (error: Throwable) {
                                                    status = "收到消息，但解密失败。"
                                                    statusTone = UiTone.DANGER
                                                }
                                            },
                                            onClose = {
                                                connected = false
                                                markOffline(friends)
                                                if (!status.contains("版本过旧")) {
                                                    status = it
                                                }
                                                statusTone = UiTone.DANGER
                                            }
                                        )
                                        socket!!.connect(clean, jwk)
                                        runOnUiThread {
                                            activeUserId = clean
                                            fingerprint = fp
                                            inviteCode = makeInvite(clean, jwk, fp)
                                            replaceFriends(friends, merged, keyChangedFriends)
                                            saveFriends(clean, friends)
                                            prefs.edit().putString("lastUserId", clean).apply()
                                            status = "正在连接 Render 服务..."
                                            statusTone = UiTone.INFO
                                        }
                                    } catch (error: Throwable) {
                                        runOnUiThread {
                                            status = "登入失败：${error.message ?: "服务不可用"}"
                                            statusTone = UiTone.DANGER
                                        }
                                    }
                                }
                            },
                            onCopyInvite = {
                                copyText("Secure Burn 邀请码", inviteCode)
                                status = "邀请代码已复制。"
                                statusTone = UiTone.SUCCESS
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
                                statusTone = UiTone.INFO
                            },
                            onWipe = { wipeConfirm = true }
                        )
                    }
                    item {
                        CompactStatusBanner(status = status, tone = statusTone)
                    }

                    if (selectedTab == AppTab.CHATS) {
                        if (activeFriend == null) {
                            item {
                                ConversationListCard(
                                    friends = friends,
                                    activeFriendId = activeFriendId,
                                    keyChangedFriends = keyChangedFriends,
                                    onSelect = {
                                        activeFriendId = it
                                        currentMessage = null
                                    }
                                )
                            }
                        } else {
                            item {
                                ChatCard(
                                    friend = activeFriend,
                                    canSend = canSend,
                                    message = message,
                                    onMessageChange = { message = it },
                                    currentMessage = currentMessage,
                                    countdownSeconds = currentMessage?.let { max(0, ((it.expiresAt - countdownNow) / 1000).toInt()) } ?: 0,
                                    keyChanged = activeKeyChanged,
                                    onBack = {
                                        activeFriendId = ""
                                        currentMessage = null
                                        message = ""
                                    },
                                    onVerifyKey = {
                                        if (activeFriendId.isNotBlank()) {
                                            keyChangedFriends.remove(activeFriendId)
                                            status = "已在本机标记 ${activeFriendId} 的新指纹为已验证。"
                                            statusTone = UiTone.SUCCESS
                                        }
                                    },
                                    onSend = {
                                        val text = message.trim()
                                        val pair = keyPair
                                        val friend = activeFriend
                                        if (text.isBlank() || pair == null) return@ChatCard
                                        if (!canSend) {
                                            status = when {
                                                activeKeyChanged -> "好友身份密钥已变更，重新验证指纹前已暂停发送。"
                                                !connected -> "连接未就绪，消息没有发送。"
                                                else -> "需要双方互相添加好友后才可发送。"
                                            }
                                            statusTone = UiTone.WARNING
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
                                            status = "消息已本地加密并提交发送，等待服务端回执。"
                                            statusTone = UiTone.INFO
                                        } catch (error: Throwable) {
                                            status = "加密失败，消息没有发送。"
                                            statusTone = UiTone.DANGER
                                        }
                                    }
                                )
                            }
                        }
                    }

                    if (selectedTab == AppTab.CONTACTS) {
                        item {
                            ContactEntryCard(
                                inviteCode = inviteCode,
                                onCopyInvite = {
                                    if (inviteCode.isNotBlank()) copyText("Secure Burn 邀请码", inviteCode)
                                    status = "邀请代码已复制。"
                                    statusTone = UiTone.SUCCESS
                                },
                                onAdd = { addFriendDialog = true }
                            )
                        }
                        item {
                            FriendsCard(
                                friends = friends,
                                activeFriendId = activeFriendId,
                                keyChangedFriends = keyChangedFriends,
                                onSelect = {
                                    activeFriendId = it
                                    selectedTab = AppTab.CHATS
                                    currentMessage = null
                                },
                                onDelete = { id ->
                                    if (activeUserId.isBlank()) return@FriendsCard
                                    scope.launch(Dispatchers.IO) {
                                        try {
                                            val result = api.deleteFriend(activeUserId, id)
                                            val incoming = parseFriends(result.optJSONArray("friends"))
                                            runOnUiThread {
                                                replaceFriends(friends, incoming, keyChangedFriends)
                                                saveFriends(activeUserId, friends)
                                                if (activeFriendId == id) activeFriendId = ""
                                                keyChangedFriends.remove(id)
                                                currentMessage = null
                                                status = "已删除好友：$id"
                                                statusTone = UiTone.SUCCESS
                                            }
                                        } catch (error: Throwable) {
                                            runOnUiThread {
                                                status = "删除好友失败：${error.message ?: "服务不可用"}"
                                                statusTone = UiTone.DANGER
                                            }
                                        }
                                    }
                                }
                            )
                        }
                    }

                    if (selectedTab == AppTab.SECURITY) {
                        item {
                            CommercialStatusCard(
                                status = status,
                                tone = statusTone,
                                connected = connected,
                                activeUserId = activeUserId,
                                activeFriend = activeFriend,
                                keyChanged = activeKeyChanged,
                                currentMessage = currentMessage,
                                countdownSeconds = currentMessage?.let { max(0, ((it.expiresAt - countdownNow) / 1000).toInt()) } ?: 0
                            )
                        }
                        item {
                            SecurityCenterCard(
                                activeUserId = activeUserId,
                                fingerprint = fingerprint,
                                inviteCode = inviteCode,
                                friends = friends,
                                keyChangedFriends = keyChangedFriends,
                                onCopyInvite = {
                                    if (inviteCode.isNotBlank()) copyText("Secure Burn 邀请码", inviteCode)
                                    status = "邀请代码已复制。"
                                    statusTone = UiTone.SUCCESS
                                },
                                onVerifyFriend = { friendIdToVerify ->
                                    keyChangedFriends.remove(friendIdToVerify)
                                    status = "已在本机标记 $friendIdToVerify 的新指纹为已验证。"
                                    statusTone = UiTone.SUCCESS
                                },
                                onWipe = { wipeConfirm = true }
                            )
                        }
                    }

                    if (selectedTab == AppTab.SETTINGS) {
                        item {
                            SettingsCard(
                                activeUserId = activeUserId,
                                connected = connected,
                                status = status,
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
                                    statusTone = UiTone.INFO
                                },
                                onWipe = { wipeConfirm = true }
                            )
                        }
                    }
                }

                if (addFriendDialog) {
                    AddFriendDialog(
                        friendId = friendId,
                        friendInvite = friendInvite,
                        onFriendIdChange = { friendId = it },
                        onFriendInviteChange = { friendInvite = it },
                        onDismiss = { addFriendDialog = false },
                        onAddFriend = {
                            if (activeUserId.isBlank()) {
                                status = "请先登入。"
                                statusTone = UiTone.WARNING
                                return@AddFriendDialog
                            }
                            scope.launch(Dispatchers.IO) {
                                try {
                                    val friend = resolveFriend(friendId.trim(), friendInvite.trim())
                                    if (friend.userId == activeUserId) error("不能添加自己")
                                    val result = api.addFriend(activeUserId, friend.userId, friend.publicKey)
                                    val incoming = parseFriends(result.optJSONArray("friends"))
                                    runOnUiThread {
                                        replaceFriends(friends, incoming, keyChangedFriends)
                                        saveFriends(activeUserId, friends)
                                        activeFriendId = friend.userId
                                        selectedTab = AppTab.CHATS
                                        addFriendDialog = false
                                        friendId = ""
                                        friendInvite = ""
                                        status = "已添加好友 ${friend.userId}，等待双向确认后可通信。"
                                        statusTone = UiTone.SUCCESS
                                    }
                                } catch (error: Throwable) {
                                    runOnUiThread {
                                        status = "添加失败：请确认好友 ID 已进入过系统，或粘贴完整邀请代码。"
                                        statusTone = UiTone.WARNING
                                    }
                                }
                            }
                        }
                    )
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
                                        statusTone = UiTone.SUCCESS
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
            if (activeUserId.isNotBlank()) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Secure Burn", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text("$activeUserId · ${if (status.contains("已连接")) "已连接" else "安全通信"}", color = Color(0xFF64748B), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    StatusPill(if (status.contains("已连接")) "端到端加密" else "已登入", true)
                }
                Spacer(Modifier.height(8.dp))
                Text("身份指纹：$fingerprint", color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                return@SectionCard
            }

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column {
                    Text("Secure Burn", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text("安全通信，从身份开始", color = Color(0xFF64748B))
                }
                StatusPill("未登入", false)
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
            Button(onClick = onLogin, modifier = Modifier.fillMaxWidth()) { Text("登入") }
            Spacer(Modifier.height(10.dp))
            Text(status, color = Color(0xFF334155), style = MaterialTheme.typography.bodyMedium)
        }
    }

    @Composable
    private fun BottomNavigationBar(selectedTab: AppTab, onSelect: (AppTab) -> Unit) {
        NavigationBar(
            containerColor = Color.White,
            modifier = Modifier.windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            AppTab.entries.forEach { tab ->
                NavigationBarItem(
                    selected = tab == selectedTab,
                    onClick = { onSelect(tab) },
                    icon = { StatusDot(if (tab == selectedTab) UiTone.SUCCESS else UiTone.INFO) },
                    label = { Text(tab.label) }
                )
            }
        }
    }

    @Composable
    private fun ContactEntryCard(inviteCode: String, onCopyInvite: () -> Unit, onAdd: () -> Unit) {
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("联系人", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text("通过邀请代码建立信任，或添加已注册 ID。", color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
                }
                Button(onClick = onAdd) { Text("添加") }
            }
            if (inviteCode.isNotBlank()) {
                Spacer(Modifier.height(12.dp))
                Text("我的邀请代码", fontWeight = FontWeight.SemiBold)
                Text(inviteCode, color = Color(0xFF64748B), maxLines = 2, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = onCopyInvite, modifier = Modifier.fillMaxWidth()) { Text("复制邀请代码") }
            }
        }
    }

    @Composable
    private fun AddFriendDialog(
        friendId: String,
        friendInvite: String,
        onFriendIdChange: (String) -> Unit,
        onFriendInviteChange: (String) -> Unit,
        onDismiss: () -> Unit,
        onAddFriend: () -> Unit
    ) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text("添加联系人") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = friendId,
                        onValueChange = onFriendIdChange,
                        label = { Text("好友 ID") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = friendInvite,
                        onValueChange = onFriendInviteChange,
                        label = { Text("或粘贴完整邀请代码") },
                        minLines = 3,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text("建议优先使用邀请代码，因为它包含对方公钥和身份指纹。", color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = { TextButton(onClick = onAddFriend) { Text("添加") } },
            dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
        )
    }

    @Composable
    private fun CompactStatusBanner(status: String, tone: UiTone) {
        val colors = toneColors(tone)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.background, RoundedCornerShape(14.dp))
                .border(1.dp, colors.border, RoundedCornerShape(14.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            StatusDot(tone)
            Spacer(Modifier.width(10.dp))
            Text(status, color = colors.foreground, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }

    @Composable
    private fun ConversationListCard(
        friends: List<Friend>,
        activeFriendId: String,
        keyChangedFriends: List<String>,
        onSelect: (String) -> Unit
    ) {
        SectionCard {
            Text("聊天", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text("会话列表不展示消息明文，只展示安全与交付状态。", color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(10.dp))
            if (friends.isEmpty()) {
                Text("暂无会话。请到“联系人”添加好友。", color = Color(0xFF64748B))
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    friends.forEach { friend ->
                        ConversationRow(
                            friend = friend,
                            selected = friend.userId == activeFriendId,
                            keyChanged = friend.userId in keyChangedFriends,
                            onSelect = { onSelect(friend.userId) }
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun ConversationRow(friend: Friend, selected: Boolean, keyChanged: Boolean, onSelect: () -> Unit) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, if (selected) Color(0xFF0F766E) else Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                .background(if (selected) Color(0xFFE6FFFA) else Color.White, RoundedCornerShape(10.dp))
                .clickable(onClick = onSelect)
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(if (keyChanged) Color(0xFFFEE2E2) else Color(0xFFE0F2FE), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(friend.userId.take(1).uppercase(), color = if (keyChanged) Color(0xFF991B1B) else Color(0xFF075985), fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(friend.userId, fontWeight = FontWeight.SemiBold)
                Text(conversationStatus(friend, keyChanged), color = toneColors(contactTone(friend, keyChanged)).foreground, style = MaterialTheme.typography.bodySmall)
                Text("最新消息状态：不显示明文预览", color = Color(0xFF94A3B8), style = MaterialTheme.typography.bodySmall)
            }
            StatusDot(contactTone(friend, keyChanged))
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
        keyChangedFriends: List<String>,
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
                    FriendGroup("密钥异常", friends.filter { it.userId in keyChangedFriends }, activeFriendId, keyChangedFriends, onSelect, onDelete)
                    FriendGroup("待确认", friends.filter { it.userId !in keyChangedFriends && !it.confirmed }, activeFriendId, keyChangedFriends, onSelect, onDelete)
                    FriendGroup("已确认", friends.filter { it.userId !in keyChangedFriends && it.confirmed }, activeFriendId, keyChangedFriends, onSelect, onDelete)
                }
            }
        }
    }

    @Composable
    private fun FriendGroup(
        title: String,
        groupFriends: List<Friend>,
        activeFriendId: String,
        keyChangedFriends: List<String>,
        onSelect: (String) -> Unit,
        onDelete: (String) -> Unit
    ) {
        if (groupFriends.isEmpty()) return
        Text(title, color = Color(0xFF64748B), fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
        groupFriends.forEach { friend ->
            FriendRow(
                friend = friend,
                selected = friend.userId == activeFriendId,
                keyChanged = friend.userId in keyChangedFriends,
                onSelect = { onSelect(friend.userId) },
                onDelete = { onDelete(friend.userId) }
            )
        }
    }

    @Composable
    private fun SecurityCenterCard(
        activeUserId: String,
        fingerprint: String,
        inviteCode: String,
        friends: List<Friend>,
        keyChangedFriends: List<String>,
        onCopyInvite: () -> Unit,
        onVerifyFriend: (String) -> Unit,
        onWipe: () -> Unit
    ) {
        SectionCard {
            Text("安全中心", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            SecurityDashboard(
                activeUserId = activeUserId,
                friends = friends,
                keyChangedFriends = keyChangedFriends
            )
            Spacer(Modifier.height(12.dp))
            StatusRow("我的 ID", activeUserId.ifBlank { "未登入" }, if (activeUserId.isBlank()) UiTone.WARNING else UiTone.SUCCESS)
            StatusRow("身份指纹", fingerprint, if (activeUserId.isBlank()) UiTone.WARNING else UiTone.SUCCESS)
            StatusRow("公钥状态", if (activeUserId.isBlank()) "未注册" else "已注册到服务器，私钥保留在本机", if (activeUserId.isBlank()) UiTone.WARNING else UiTone.SUCCESS)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onCopyInvite, enabled = inviteCode.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                Text("复制我的邀请代码")
            }
            Spacer(Modifier.height(12.dp))
            Text("好友指纹验证", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            if (friends.isEmpty()) {
                Text("暂无好友可验证。", color = Color(0xFF64748B))
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    friends.forEach { friend ->
                        val changed = friend.userId in keyChangedFriends
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .border(1.dp, toneColors(contactTone(friend, changed)).border, RoundedCornerShape(10.dp))
                                .padding(10.dp)
                        ) {
                            Text(friend.userId, fontWeight = FontWeight.SemiBold)
                            Text(contactState(friend, changed), color = toneColors(contactTone(friend, changed)).foreground)
                            Text("指纹：${friend.fingerprint}", color = Color(0xFF64748B), maxLines = 2, overflow = TextOverflow.Ellipsis)
                            if (changed) {
                                Spacer(Modifier.height(6.dp))
                                OutlinedButton(onClick = { onVerifyFriend(friend.userId) }, modifier = Modifier.fillMaxWidth()) {
                                    Text("标记为已重新验证")
                                }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            NoticeBlock("删除所有记录会清除本机身份密钥、好友缓存、当前消息，并请求服务端删除账号资料。", UiTone.DANGER)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onWipe, colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFB91C1C)), modifier = Modifier.fillMaxWidth()) {
                Text("删除所有记录")
            }
        }
    }

    @Composable
    private fun SecurityDashboard(activeUserId: String, friends: List<Friend>, keyChangedFriends: List<String>) {
        val verifiedCount = friends.count { it.confirmed && it.userId !in keyChangedFriends }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                MetricTile("身份密钥", if (activeUserId.isBlank()) "未加载" else "正常", if (activeUserId.isBlank()) UiTone.WARNING else UiTone.SUCCESS, Modifier.weight(1f))
                MetricTile("好友验证", "$verifiedCount/${friends.size}", if (verifiedCount == friends.size && friends.isNotEmpty()) UiTone.SUCCESS else UiTone.WARNING, Modifier.weight(1f))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                MetricTile("密钥异常", keyChangedFriends.size.toString(), if (keyChangedFriends.isEmpty()) UiTone.SUCCESS else UiTone.DANGER, Modifier.weight(1f))
                MetricTile("本机数据", "仅设备", UiTone.SUCCESS, Modifier.weight(1f))
            }
            MetricTile("服务器存储", "不保存消息明文；仅保存用户公钥和好友关系", UiTone.SUCCESS, Modifier.fillMaxWidth())
        }
    }

    @Composable
    private fun MetricTile(label: String, value: String, tone: UiTone, modifier: Modifier = Modifier) {
        val colors = toneColors(tone)
        Column(
            modifier
                .background(colors.background, RoundedCornerShape(12.dp))
                .border(1.dp, colors.border, RoundedCornerShape(12.dp))
                .padding(10.dp)
        ) {
            Text(label, color = Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
            Text(value, color = colors.foreground, fontWeight = FontWeight.Bold, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }

    @Composable
    private fun SettingsCard(
        activeUserId: String,
        connected: Boolean,
        status: String,
        onLogout: () -> Unit,
        onWipe: () -> Unit
    ) {
        SectionCard {
            Text("设置", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            Text("账号", fontWeight = FontWeight.SemiBold)
            StatusRow("当前账号", activeUserId.ifBlank { "未登入" }, if (activeUserId.isBlank()) UiTone.WARNING else UiTone.SUCCESS)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = onLogout, enabled = activeUserId.isNotBlank(), modifier = Modifier.weight(1f)) { Text("退出登录") }
                OutlinedButton(onClick = onWipe, colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFB91C1C)), modifier = Modifier.weight(1f)) { Text("删除账号") }
            }
            Spacer(Modifier.height(12.dp))
            Text("隐私", fontWeight = FontWeight.SemiBold)
            StatusRow("禁止截图", "已启用 FLAG_SECURE", UiTone.SUCCESS)
            StatusRow("后台隐藏内容", "随系统安全窗口策略处理", UiTone.INFO)
            StatusRow("剪贴板", "邀请代码复制后请通过系统剪贴板管理清除", UiTone.WARNING)
            Spacer(Modifier.height(12.dp))
            Text("通知", fontWeight = FontWeight.SemiBold)
            StatusRow("通知内容", "默认不展示消息明文", UiTone.SUCCESS)
            StatusRow("发送人显示", "后续接入系统通知权限时默认隐藏", UiTone.INFO)
            Spacer(Modifier.height(12.dp))
            Text("网络", fontWeight = FontWeight.SemiBold)
            StatusRow("服务器", BuildConfig.SERVER_BASE_URL, UiTone.INFO)
            StatusRow("连接状态", if (connected) "已连接" else "未连接或已断开", if (connected) UiTone.SUCCESS else UiTone.WARNING)
            StatusRow("当前状态", status, if (connected) UiTone.SUCCESS else UiTone.INFO)
            Spacer(Modifier.height(12.dp))
            Text("开发者 / 测试", fontWeight = FontWeight.SemiBold)
            StatusRow("明文捕获测试模式", "App 不主动提交；仅服务端测试开关控制", UiTone.SUCCESS)
            StatusRow("调试日志", "未在 App 内展示消息明文日志", UiTone.SUCCESS)
            Spacer(Modifier.height(12.dp))
            Text("关于", fontWeight = FontWeight.SemiBold)
            StatusRow("版本", "Android ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})", UiTone.INFO)
            StatusRow("协议", "demo-ecdh-v1，生产版仍需 libsignal", UiTone.WARNING)
        }
    }

    @Composable
    private fun CommercialStatusCard(
        status: String,
        tone: UiTone,
        connected: Boolean,
        activeUserId: String,
        activeFriend: Friend?,
        keyChanged: Boolean,
        currentMessage: VisibleMessage?,
        countdownSeconds: Int
    ) {
        SectionCard {
            Text("系统状态", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            NoticeBlock(status, tone)
            Spacer(Modifier.height(10.dp))
            StatusRow("服务器连接", if (connected) "已连接" else if (activeUserId.isBlank()) "未登入" else "断开或重连中", if (connected) UiTone.SUCCESS else UiTone.WARNING)
            StatusRow("WebSocket", if (connected) "实时通道正常" else "不可用，消息不会发送", if (connected) UiTone.SUCCESS else UiTone.DANGER)
            StatusRow("本机身份密钥", if (activeUserId.isBlank()) "未加载" else "已在 Android Keystore 中加载", if (activeUserId.isBlank()) UiTone.WARNING else UiTone.SUCCESS)
            StatusRow("联系人安全", contactState(activeFriend, keyChanged), contactTone(activeFriend, keyChanged))
            StatusRow("消息窗口", if (currentMessage == null) "空，当前不保留聊天记录" else "最后一条消息 ${formatCountdown(countdownSeconds)} 后清除", if (currentMessage == null) UiTone.INFO else UiTone.WARNING)
            StatusRow("客户端版本", "Android ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})", UiTone.INFO)
        }
    }

    @Composable
    private fun NoticeBlock(text: String, tone: UiTone) {
        val colors = toneColors(tone)
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.background, RoundedCornerShape(10.dp))
                .border(1.dp, colors.border, RoundedCornerShape(10.dp))
                .padding(10.dp)
        ) {
            Text(toneTitle(tone), color = colors.foreground, fontWeight = FontWeight.Bold)
            Text(text, color = colors.foreground, style = MaterialTheme.typography.bodyMedium)
        }
    }

    @Composable
    private fun StatusRow(label: String, value: String, tone: UiTone) {
        Row(
            Modifier.fillMaxWidth().padding(vertical = 5.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Text(label, color = Color(0xFF64748B), modifier = Modifier.weight(0.38f))
            Text(value, color = toneColors(tone).foreground, modifier = Modifier.weight(0.62f), fontWeight = FontWeight.SemiBold)
        }
    }

    @Composable
    private fun FriendRow(friend: Friend, selected: Boolean, keyChanged: Boolean, onSelect: () -> Unit, onDelete: () -> Unit) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, if (keyChanged) Color(0xFFFCA5A5) else if (selected) Color(0xFF0F766E) else Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                .background(if (selected) Color(0xFFE6FFFA) else Color.White, RoundedCornerShape(10.dp))
                .clickable(onClick = onSelect)
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .background(if (keyChanged) Color(0xFFDC2626) else if (friend.online) Color(0xFF16A34A) else if (friend.confirmed) Color(0xFF94A3B8) else Color(0xFFF59E0B), CircleShape)
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(friend.userId, fontWeight = FontWeight.SemiBold)
                Text(if (keyChanged) "身份密钥已变更，需重新验证" else friendState(friend), color = if (keyChanged) Color(0xFFB91C1C) else Color(0xFF64748B), style = MaterialTheme.typography.bodySmall)
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
        keyChanged: Boolean,
        onBack: () -> Unit,
        onVerifyKey: () -> Unit,
        onSend: () -> Unit
    ) {
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("返回") }
                Column(Modifier.weight(1f), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(friend?.userId ?: "请选择好友", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text(chatSubtitle(friend, keyChanged), color = if (keyChanged) Color(0xFFB91C1C) else Color(0xFF64748B), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                StatusDot(contactTone(friend, keyChanged))
            }
            if (keyChanged) {
                Spacer(Modifier.height(8.dp))
                NoticeBlock("好友身份密钥已变化。这可能是换设备，也可能是中间人攻击。重新核对指纹前，发送已暂停。", UiTone.DANGER)
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = onVerifyKey, modifier = Modifier.fillMaxWidth()) {
                    Text("我已通过可信渠道核对新指纹")
                }
            }
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
        onStatus: (String, UiTone) -> Unit,
        onMessage: (JSONObject) -> Unit,
        onClose: (String) -> Unit
    ): SecureBurnSocket {
        val clientInfo = JSONObject()
            .put("platform", "android")
            .put("versionName", BuildConfig.VERSION_NAME)
            .put("versionCode", BuildConfig.VERSION_CODE)
        return SecureBurnSocket(BuildConfig.SERVER_BASE_URL, clientInfo) { event ->
            runOnUiThread {
                when (event.optString("type")) {
                    "ready" -> onReady(event)
                    "friends" -> onFriends(parseFriends(event.optJSONArray("friends")))
                    "message" -> onMessage(event)
                    "sent" -> {
                        when (event.optString("delivery")) {
                            "delivered" -> onStatus("密文已送达：${event.optString("to")}", UiTone.SUCCESS)
                            "queued" -> onStatus("密文已进入短期离线队列。", UiTone.INFO)
                            "rejected" -> onStatus("密文被拒收：对方队列已满或策略拒绝。", UiTone.DANGER)
                            else -> onStatus("服务端已接收发送请求。", UiTone.INFO)
                        }
                    }
                    "delivered" -> onStatus("密文已送达：${event.optString("to")}", UiTone.SUCCESS)
                    "expired" -> onStatus("密文未送达并已过期：${event.optString("reason", "超过 TTL")}", UiTone.WARNING)
                    "keyChanged" -> {
                        onFriends(parseFriends(event.optJSONArray("friends")))
                        onStatus("${event.optString("userId")} 的身份密钥发生变化，请重新核对指纹。", UiTone.DANGER)
                    }
                    "accountDeleted" -> onClose("账号记录已删除。")
                    "clientOutdated" -> onStatus(event.optString("message", "当前客户端版本过旧，请更新后继续使用。"), UiTone.DANGER)
                    "error" -> onStatus(event.optString("message", "服务端返回错误。"), UiTone.WARNING)
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

    private fun replaceFriends(target: MutableList<Friend>, incoming: List<Friend>, keyChangedFriends: MutableList<String>? = null) {
        val previous = target.associateBy { it.userId }
        if (keyChangedFriends != null) {
            for (friend in incoming) {
                val old = previous[friend.userId]
                if (old != null && old.fingerprint != friend.fingerprint && friend.userId !in keyChangedFriends) {
                    keyChangedFriends.add(friend.userId)
                }
            }
        }
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
        return if (friend.online) "在线，可发送" else "离线，可排队"
    }

    private fun conversationStatus(friend: Friend, keyChanged: Boolean): String {
        if (keyChanged) return "身份密钥已变更 · 需要重新验证"
        if (!friend.confirmed) return "待对方确认 · 暂不可发送"
        if (!friend.online) return "已双向确认 · 离线排队"
        return "双向确认 · 在线"
    }

    @Composable
    private fun StatusDot(tone: UiTone) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .background(toneColors(tone).foreground, CircleShape)
        )
    }

    private fun chatSubtitle(friend: Friend?, keyChanged: Boolean = false): String {
        if (friend == null) return "双方互相添加后可发送。好友离线时进入短期密文队列。"
        if (keyChanged) return "身份密钥已变更，重新验证前已暂停发送。"
        if (!friend.confirmed) return "等待对方也添加你，完成双向确认。"
        if (!friend.online) return "好友离线，发送后进入短期密文队列。"
        return "双向确认且在线，可发送端到端加密消息。"
    }

    private fun contactState(friend: Friend?, keyChanged: Boolean): String {
        if (friend == null) return "未选择联系人"
        if (keyChanged) return "密钥已变更，发送已暂停"
        if (!friend.confirmed) return "未双向确认，暂不可发送"
        if (!friend.online) return "已确认，离线排队"
        return "已确认且在线"
    }

    private fun contactTone(friend: Friend?, keyChanged: Boolean): UiTone {
        if (friend == null) return UiTone.INFO
        if (keyChanged) return UiTone.DANGER
        if (!friend.confirmed || !friend.online) return UiTone.WARNING
        return UiTone.SUCCESS
    }

    private fun toneTitle(tone: UiTone): String = when (tone) {
        UiTone.SUCCESS -> "正常"
        UiTone.INFO -> "信息"
        UiTone.WARNING -> "需要注意"
        UiTone.DANGER -> "高风险"
    }

    private fun toneColors(tone: UiTone): ToneColors = when (tone) {
        UiTone.SUCCESS -> ToneColors(Color(0xFFD1FAE5), Color(0xFFA7F3D0), Color(0xFF065F46))
        UiTone.INFO -> ToneColors(Color(0xFFE0F2FE), Color(0xFFBAE6FD), Color(0xFF075985))
        UiTone.WARNING -> ToneColors(Color(0xFFFEF3C7), Color(0xFFFDE68A), Color(0xFF92400E))
        UiTone.DANGER -> ToneColors(Color(0xFFFEE2E2), Color(0xFFFECACA), Color(0xFF991B1B))
    }

    private fun formatCountdown(totalSeconds: Int): String {
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return "$minutes:${seconds.toString().padStart(2, '0')}"
    }

    private enum class UiTone {
        SUCCESS,
        INFO,
        WARNING,
        DANGER
    }

    private enum class AppTab(val label: String) {
        CHATS("聊天"),
        CONTACTS("联系人"),
        SECURITY("安全"),
        SETTINGS("设置")
    }

    private data class ToneColors(
        val background: Color,
        val border: Color,
        val foreground: Color
    )

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
