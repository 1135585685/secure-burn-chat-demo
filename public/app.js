const els = {
  userId: document.querySelector("#userId"),
  startBtn: document.querySelector("#startBtn"),
  logoutBtn: document.querySelector("#logoutBtn"),
  wipeBtn: document.querySelector("#wipeBtn"),
  sessionActions: document.querySelector("#sessionActions"),
  connectionState: document.querySelector("#connectionState"),
  identityFingerprint: document.querySelector("#identityFingerprint"),
  inviteCode: document.querySelector("#inviteCode"),
  copyInviteBtn: document.querySelector("#copyInviteBtn"),
  friendId: document.querySelector("#friendId"),
  friendInvite: document.querySelector("#friendInvite"),
  addFriendBtn: document.querySelector("#addFriendBtn"),
  friendList: document.querySelector("#friendList"),
  friendSummary: document.querySelector("#friendSummary"),
  chatTitle: document.querySelector("#chatTitle"),
  chatSubtitle: document.querySelector("#chatSubtitle"),
  securityStatus: document.querySelector("#securityStatus"),
  messages: document.querySelector("#messages"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  sendBtn: document.querySelector("#sendBtn")
};

const MESSAGE_TTL_SECONDS = 15 * 60;
const IDENTITY_DB = "secureBurnIdentityDb";
const IDENTITY_STORE = "identityKeys";

const state = {
  userId: "",
  socket: null,
  connected: false,
  keyPair: null,
  publicJwk: null,
  fingerprint: "",
  friends: new Map(),
  activeFriendId: "",
  visibleSender: "",
  messageTimer: null
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

boot();

async function boot() {
  showEmpty("先输入你的 ID 进入，再添加好友。");
  const lastUserId = localStorage.getItem("secureBurnLastUserId");
  if (lastUserId) els.userId.value = lastUserId;
  renderFriends();
  syncComposerState();
}

els.startBtn.addEventListener("click", async () => {
  const userId = els.userId.value.trim();
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(userId)) {
    return toast("ID 只能包含字母、数字、下划线和短横线，长度 3-32。");
  }

  try {
    els.startBtn.disabled = true;
    await loadOrCreateIdentity(userId);
    restoreFriends(userId);
    await registerProfile();
    renderFriends();
    renderSession();
    connect(userId);
  } catch {
    toast("进入失败：服务端不可用或注册公钥失败。");
  } finally {
    els.startBtn.disabled = false;
  }
});

els.logoutBtn.addEventListener("click", () => {
  logout();
  toast("已退出，本机当前会话已清空。");
});

els.wipeBtn.addEventListener("click", async () => {
  if (!state.userId) return;
  const confirmed = window.confirm("这会删除本机身份密钥、好友缓存、当前消息，并从服务端删除你的用户资料和好友关系。确认继续？");
  if (!confirmed) return;
  const userId = state.userId;
  try {
    await api("/api/users", {
      method: "DELETE",
      body: JSON.stringify({ userId })
    });
  } catch {
    toast("服务端删除失败，本机记录仍会清除。");
  }
  await wipeLocalUser(userId);
  resetSession();
  toast("所有本机记录已删除，服务端资料已请求删除。");
});

els.copyInviteBtn.addEventListener("click", async () => {
  if (!els.inviteCode.value) return;
  await navigator.clipboard.writeText(els.inviteCode.value);
  toast("邀请代码已复制。");
});

els.addFriendBtn.addEventListener("click", async () => {
  if (!state.userId) return toast("请先输入你的 ID 并进入。");
  try {
    await registerProfile();
    const friend = await resolveFriend();
    if (!friend.userId || !friend.publicKey) throw new Error("bad friend");
    if (friend.userId === state.userId) return toast("不能添加自己。");
    const saved = await api("/api/friends", {
      method: "POST",
      body: JSON.stringify({ userId: state.userId, friend })
    });
    replaceFriends(saved.friends);
    saveFriends();
    renderFriends();
    els.friendId.value = "";
    els.friendInvite.value = "";
    selectFriend(friend.userId);
    toast(`已添加好友：${friend.userId}`);
  } catch {
    toast("添加失败：对方需要先登入一次，或粘贴对方完整邀请代码。");
  }
});

els.messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = els.messageInput.value.trim();
  if (!text) return;
  if (!state.activeFriendId) return toast("请先选择好友。");
  if (!state.socket || state.socket.readyState !== WebSocket.OPEN) return toast("连接未就绪，消息没有发送。");
  const friend = state.friends.get(state.activeFriendId);
  if (!friend?.publicKey) return toast("缺少好友公钥，无法加密。请重新添加好友。");
  if (!friend.confirmed) return toast("消息未发送：需要双方互相添加好友。");
  if (!friend.online) return toast("消息未发送：好友当前不在线。");
  const burnAfter = MESSAGE_TTL_SECONDS;
  try {
    const encrypted = await encryptForFriend(friend, { text, burnAfter, sentAt: Date.now() });
    state.socket.send(JSON.stringify({
      type: "message",
      from: state.userId,
      to: friend.userId,
      encrypted
    }));
    addMessage({ from: state.userId, text, burnAfter, mine: true, status: "已加密发送" });
    els.messageInput.value = "";
  } catch {
    toast("加密失败，消息没有发送。");
  }
});

async function loadOrCreateIdentity(userId) {
  const saved = loadProfile(userId);
  const storedKey = await loadIdentityKey(userId);
  if (storedKey?.privateKey && saved?.publicJwk) {
    state.publicJwk = saved.publicJwk;
    state.keyPair = {
      privateKey: storedKey.privateKey,
      publicKey: await crypto.subtle.importKey(
        "jwk",
        saved.publicJwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      )
    };
  } else if (saved?.userId === userId && saved.privateJwk && saved.publicJwk) {
    state.publicJwk = saved.publicJwk;
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      saved.privateJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );
    state.keyPair = {
      privateKey,
      publicKey: await crypto.subtle.importKey(
        "jwk",
        saved.publicJwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      )
    };
    await saveIdentityKey(userId, privateKey);
  } else {
    state.keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );
    state.publicJwk = await crypto.subtle.exportKey("jwk", state.keyPair.publicKey);
    await saveIdentityKey(userId, state.keyPair.privateKey);
  }

  state.userId = userId;
  state.fingerprint = await fingerprintPublicKey(state.publicJwk);
  localStorage.setItem(`secureBurnProfile:${userId}`, JSON.stringify({
    userId,
    publicJwk: state.publicJwk,
    fingerprint: state.fingerprint
  }));
  localStorage.setItem("secureBurnLastUserId", userId);
  els.inviteCode.value = makeInvite(userId, state.publicJwk, state.fingerprint);
  renderIdentityFingerprint();
}

async function registerProfile() {
  const result = await api("/api/register", {
    method: "POST",
    body: JSON.stringify({ userId: state.userId, publicKey: state.publicJwk })
  });
  replaceFriends(result.friends);
  saveFriends();
}

function connect(userId) {
  state.socket?.close();
  state.connected = false;
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  state.socket = new WebSocket(`${protocol}://${location.host}`);
  els.connectionState.textContent = "正在连接...";

  state.socket.addEventListener("open", () => {
    state.socket.send(JSON.stringify({ type: "hello", userId, publicKey: state.publicJwk }));
  });

  state.socket.addEventListener("message", async (event) => {
    const packet = JSON.parse(event.data);
    if (packet.type === "ready") {
      state.connected = true;
      mergeFriends(packet.friends);
      saveFriends();
      renderFriends();
      els.connectionState.textContent = `已连接：${packet.userId}`;
      els.securityStatus.textContent = "端到端加密已启用";
      syncComposerState();
      return;
    }
    if (packet.type === "friends") {
      replaceFriends(packet.friends);
      saveFriends();
      renderFriends();
      syncComposerState();
      return;
    }
    if (packet.type === "accountDeleted") {
      const userId = state.userId;
      if (userId) await wipeLocalUser(userId);
      resetSession();
      toast("账号记录已删除。");
      return;
    }
    if (packet.type === "sent") {
      toast(packet.delivery === "delivered" ? `密文已送达：${packet.to}` : `密文已进入短期队列：${packet.to}`);
      return;
    }
    if (packet.type === "delivered") {
      toast(`密文已送达：${packet.to}`);
      return;
    }
    if (packet.type === "expired") {
      toast(`密文未送达并已过期：${packet.to}`);
      return;
    }
    if (packet.type === "keyChanged") {
      replaceFriends(packet.friends);
      saveFriends();
      renderFriends();
      syncComposerState();
      toast(`${packet.userId} 的身份密钥发生变化，请重新核对指纹。`);
      return;
    }
    if (packet.type === "error") {
      toast(packet.message || "服务端返回错误。");
      return;
    }
    if (packet.type === "message") {
      await handleEncryptedMessage(packet);
    }
  });

  state.socket.addEventListener("close", () => {
    state.connected = false;
    els.connectionState.textContent = "连接已断开";
    els.securityStatus.textContent = "等待重新连接";
    markAllOffline();
    renderFriends();
    syncComposerState();
  });

  state.socket.addEventListener("error", () => {
    toast("WebSocket 连接失败。");
  });
}

async function handleEncryptedMessage(packet) {
  const friend = state.friends.get(packet.from);
  if (!friend) {
    toast(`收到来自 ${packet.from} 的密文，但还未添加此好友。`);
    return;
  }
  try {
    const payload = await decryptFromFriend(friend, packet.encrypted);
    if (!state.activeFriendId) selectFriend(friend.userId);
    addMessage({ from: friend.userId, text: payload.text, burnAfter: payload.burnAfter || MESSAGE_TTL_SECONDS, mine: false, status: "已解密" });
  } catch {
    toast("收到一条无法解密的消息。");
  }
}

async function encryptForFriend(friend, payload) {
  const key = await deriveAesKey(friend.publicKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    version: 1,
    alg: "ECDH-P256+AES-GCM",
    protocol: "demo-ecdh-v1",
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext))
  };
}

async function decryptFromFriend(friend, encrypted) {
  const key = await deriveAesKey(friend.publicKey);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(encrypted.iv) },
    key,
    fromBase64(encrypted.ciphertext)
  );
  return JSON.parse(decoder.decode(plaintext));
}

async function deriveAesKey(friendPublicJwk) {
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    friendPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    state.keyPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function addMessage({ from, text, burnAfter, mine, status }) {
  const senderKey = mine ? "me" : from;
  if (state.visibleSender && state.visibleSender !== senderKey) {
    els.messages.innerHTML = "";
  }
  state.visibleSender = senderKey;
  clearMessageTimer();
  if (els.messages.querySelector(".empty")) els.messages.innerHTML = "";
  const node = document.createElement("article");
  node.className = `message ${mine ? "mine" : ""}`;
  node.innerHTML = `
    <div></div>
    <p class="meta"><span class="burning"></span> · ${escapeHtml(from)} · ${escapeHtml(status || "本地显示")}</p>
  `;
  node.firstElementChild.textContent = text;
  els.messages.append(node);
  els.messages.scrollTop = els.messages.scrollHeight;

  const burning = node.querySelector(".burning");
  const expiresAt = Date.now() + burnAfter * 1000;
  state.messageTimer = setInterval(() => {
    const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    burning.textContent = `${formatCountdown(left)} 后消失`;
    if (left <= 0) {
      clearMessageTimer();
      showEmpty("单消息窗口已清空，本地不保留聊天记录。");
    }
  }, 250);
}

function selectFriend(userId) {
  state.activeFriendId = userId;
  els.chatTitle.textContent = userId;
  syncComposerState();
  renderFriends();
}

function renderFriends() {
  els.friendSummary.textContent = `${state.friends.size} 位`;
  if (!state.friends.size) {
    els.friendList.innerHTML = `<p class="hint">暂无好友。用 ID 或邀请代码添加一个联系人。</p>`;
    return;
  }
  els.friendList.innerHTML = "";
  for (const friend of state.friends.values()) {
    const row = document.createElement("div");
    row.className = `friend ${friend.userId === state.activeFriendId ? "active" : ""}`;
    row.innerHTML = `
      <button class="friend-main" type="button">
        <span class="presence ${friend.online ? "online" : friend.confirmed ? "offline" : "pending"}"></span>
        <span>
          <strong>${escapeHtml(friend.userId)}</strong>
          <small>${escapeHtml(friendLabel(friend))}</small>
          <small class="fingerprint">${escapeHtml(friend.fingerprint || "无指纹")}</small>
        </span>
      </button>
      <button class="danger-btn" type="button" title="删除好友">删除</button>
    `;
    row.querySelector(".friend-main").addEventListener("click", () => selectFriend(friend.userId));
    row.querySelector(".danger-btn").addEventListener("click", () => deleteFriend(friend.userId));
    els.friendList.append(row);
  }
}

async function deleteFriend(friendId) {
  if (!state.userId) return;
  try {
    const result = await api("/api/friends", {
      method: "DELETE",
      body: JSON.stringify({ userId: state.userId, friendId })
    });
    replaceFriends(result.friends);
    saveFriends();
    if (state.activeFriendId === friendId) {
      state.activeFriendId = "";
      els.chatTitle.textContent = "请选择好友";
      els.chatSubtitle.textContent = "双方互相添加且在线后才可发送。";
      showEmpty("好友已删除。");
    }
    renderFriends();
    syncComposerState();
    toast(`已删除好友：${friendId}`);
  } catch {
    toast("删除失败，请稍后再试。");
  }
}

async function resolveFriend() {
  const rawInvite = els.friendInvite.value.trim();
  const rawId = els.friendId.value.trim();
  if (rawInvite) return parseInvite(rawInvite);
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(rawId)) throw new Error("bad id");
  try {
    const result = await api(`/api/users/${encodeURIComponent(rawId)}`);
    return { userId: result.userId, publicKey: result.publicKey, fingerprint: result.fingerprint || await fingerprintPublicKey(result.publicKey) };
  } catch (error) {
    const localProfile = loadProfile(rawId);
    if (localProfile?.publicJwk) {
      return { userId: rawId, publicKey: localProfile.publicJwk, fingerprint: localProfile.fingerprint || await fingerprintPublicKey(localProfile.publicJwk) };
    }
    throw error;
  }
}

function makeInvite(userId, publicKey, fingerprint) {
  return btoaUnicode(JSON.stringify({ userId, publicKey, fingerprint }));
}

function parseInvite(value) {
  return JSON.parse(atobUnicode(value));
}

function saveFriends() {
  if (!state.userId) return;
  localStorage.setItem(`secureBurnFriends:${state.userId}`, JSON.stringify([...state.friends.values()]));
}

function restoreFriends(userId) {
  state.friends.clear();
  try {
    const friends = JSON.parse(localStorage.getItem(`secureBurnFriends:${userId}`) || "[]");
    for (const friend of friends) state.friends.set(friend.userId, friend);
  } catch {
    localStorage.removeItem(`secureBurnFriends:${userId}`);
  }
}

function mergeFriends(friends = []) {
  for (const friend of friends) {
    if (!friend?.userId || !friend?.publicKey) continue;
    const current = state.friends.get(friend.userId);
    const keyChanged = Boolean(current?.fingerprint && friend.fingerprint && current.fingerprint !== friend.fingerprint);
    state.friends.set(friend.userId, { ...friend, keyChanged });
    if (keyChanged) {
      toast(`${friend.userId} 的身份密钥已变更，请核对指纹。`);
    }
  }
}

function replaceFriends(friends = []) {
  state.friends.clear();
  mergeFriends(friends);
}

function markAllOffline() {
  for (const friend of state.friends.values()) friend.online = false;
}

function logout() {
  state.socket?.close();
  resetSession({ keepUserInput: true });
}

function resetSession({ keepUserInput = false } = {}) {
  clearMessageTimer();
  state.socket = null;
  state.connected = false;
  state.keyPair = null;
  state.publicJwk = null;
  state.fingerprint = "";
  state.userId = "";
  state.friends.clear();
  state.activeFriendId = "";
  state.visibleSender = "";
  els.inviteCode.value = "";
  if (!keepUserInput) els.userId.value = "";
  els.friendId.value = "";
  els.friendInvite.value = "";
  els.chatTitle.textContent = "请选择好友";
  els.securityStatus.textContent = "等待身份密钥";
  els.connectionState.textContent = "未连接";
  els.identityFingerprint.textContent = "身份指纹：未生成";
  showEmpty("已退出。输入 ID 后可重新进入。");
  renderSession();
  renderFriends();
  syncComposerState();
}

function renderSession() {
  const loggedIn = Boolean(state.userId);
  els.sessionActions.hidden = !loggedIn;
  els.startBtn.textContent = loggedIn ? "登入" : "进入";
}

async function wipeLocalUser(userId) {
  localStorage.removeItem(`secureBurnProfile:${userId}`);
  localStorage.removeItem(`secureBurnFriends:${userId}`);
  await deleteIdentityKey(userId);
  if (localStorage.getItem("secureBurnLastUserId") === userId) {
    localStorage.removeItem("secureBurnLastUserId");
  }
}

function syncComposerState() {
  const friend = state.friends.get(state.activeFriendId);
  const canSend = Boolean(state.userId && friend?.confirmed && friend?.online && state.connected);
  els.messageInput.disabled = !canSend;
  els.sendBtn.disabled = !canSend;
  if (!state.activeFriendId) {
    els.chatSubtitle.textContent = "双方互相添加且在线后才可发送。";
  } else if (!friend?.confirmed) {
    els.chatSubtitle.textContent = "等待对方也添加你，完成双向确认。";
  } else if (!friend.online) {
    els.chatSubtitle.textContent = "好友离线，暂不可发送。";
  } else {
    els.chatSubtitle.textContent = "双向确认且在线，可发送端到端加密消息。";
  }
}

function friendLabel(friend) {
  if (friend.keyChanged) return "密钥已变更，请核对";
  if (!friend.confirmed) return "待对方确认";
  return friend.online ? "在线，可发送" : "离线";
}

function renderIdentityFingerprint() {
  els.identityFingerprint.textContent = state.fingerprint ? `身份指纹：${state.fingerprint}` : "身份指纹：未生成";
}

function clearMessageTimer() {
  if (state.messageTimer) clearInterval(state.messageTimer);
  state.messageTimer = null;
}

function showEmpty(text) {
  clearMessageTimer();
  state.visibleSender = "";
  els.messages.innerHTML = `<p class="empty">${escapeHtml(text)}</p>`;
}

function formatCountdown(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ok === false) throw new Error(body.error || "Request failed");
  return body;
}

function loadProfile(userId) {
  try {
    return JSON.parse(localStorage.getItem(`secureBurnProfile:${userId}`) || "null");
  } catch {
    return null;
  }
}

function toast(message) {
  els.connectionState.textContent = message;
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function btoaUnicode(value) {
  return btoa(String.fromCharCode(...encoder.encode(value)));
}

function atobUnicode(value) {
  return decoder.decode(fromBase64(value));
}

function openIdentityDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(IDENTITY_DB, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(IDENTITY_STORE, { keyPath: "userId" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadIdentityKey(userId) {
  const db = await openIdentityDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(IDENTITY_STORE, "readonly").objectStore(IDENTITY_STORE).get(userId);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function saveIdentityKey(userId, privateKey) {
  const db = await openIdentityDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(IDENTITY_STORE, "readwrite").objectStore(IDENTITY_STORE).put({ userId, privateKey, updatedAt: Date.now() });
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function deleteIdentityKey(userId) {
  const db = await openIdentityDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(IDENTITY_STORE, "readwrite").objectStore(IDENTITY_STORE).delete(userId);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function fingerprintPublicKey(publicKey) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(canonicalJson(publicKey)));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .match(/.{1,4}/g)
    .slice(0, 8)
    .join(" ");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}
