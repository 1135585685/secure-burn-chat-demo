const els = {
  userId: document.querySelector("#userId"),
  startBtn: document.querySelector("#startBtn"),
  connectionState: document.querySelector("#connectionState"),
  inviteCode: document.querySelector("#inviteCode"),
  copyInviteBtn: document.querySelector("#copyInviteBtn"),
  friendId: document.querySelector("#friendId"),
  friendInvite: document.querySelector("#friendInvite"),
  addFriendBtn: document.querySelector("#addFriendBtn"),
  friendList: document.querySelector("#friendList"),
  chatTitle: document.querySelector("#chatTitle"),
  securityStatus: document.querySelector("#securityStatus"),
  messages: document.querySelector("#messages"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  burnAfter: document.querySelector("#burnAfter"),
  sendBtn: document.querySelector("#sendBtn")
};

const state = {
  userId: "",
  socket: null,
  connected: false,
  keyPair: null,
  publicJwk: null,
  privateJwk: null,
  friends: new Map(),
  activeFriendId: ""
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

boot();

async function boot() {
  els.messages.innerHTML = `<p class="empty">先输入你的 ID 进入，再用邀请代码添加好友。</p>`;
  const lastUserId = localStorage.getItem("secureBurnLastUserId");
  if (lastUserId) els.userId.value = lastUserId;
  renderFriends();
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
    connect(userId);
  } catch {
    toast("进入失败：服务端不可用或注册公钥失败。");
  } finally {
    els.startBtn.disabled = false;
  }
});

els.copyInviteBtn.addEventListener("click", async () => {
  if (!els.inviteCode.value) return;
  await navigator.clipboard.writeText(els.inviteCode.value);
  toast("邀请代码已复制。");
});

els.addFriendBtn.addEventListener("click", async () => {
  if (!state.userId) return toast("请先输入你的 ID 并进入。");
  try {
    const friend = await resolveFriend();
    if (!friend.userId || !friend.publicKey) throw new Error("bad friend");
    if (friend.userId === state.userId) return toast("不能添加自己。");
    const saved = await api("/api/friends", {
      method: "POST",
      body: JSON.stringify({ userId: state.userId, friend })
    });
    mergeFriends(saved.friends);
    saveFriends();
    renderFriends();
    els.friendId.value = "";
    els.friendInvite.value = "";
    selectFriend(friend.userId);
    toast(`已添加好友：${friend.userId}`);
  } catch {
    toast("添加失败：请确认好友 ID 已进入过系统，或粘贴完整邀请代码。");
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
  const burnAfter = Number(els.burnAfter.value);
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
  if (saved?.userId === userId && saved.privateJwk && saved.publicJwk) {
    state.privateJwk = saved.privateJwk;
    state.publicJwk = saved.publicJwk;
    state.keyPair = {
      privateKey: await crypto.subtle.importKey(
        "jwk",
        saved.privateJwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"]
      ),
      publicKey: await crypto.subtle.importKey(
        "jwk",
        saved.publicJwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      )
    };
  } else {
    state.keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );
    state.publicJwk = await crypto.subtle.exportKey("jwk", state.keyPair.publicKey);
    state.privateJwk = await crypto.subtle.exportKey("jwk", state.keyPair.privateKey);
  }

  state.userId = userId;
  localStorage.setItem(`secureBurnProfile:${userId}`, JSON.stringify({
    userId,
    publicJwk: state.publicJwk,
    privateJwk: state.privateJwk
  }));
  localStorage.setItem("secureBurnLastUserId", userId);
  els.inviteCode.value = makeInvite(userId, state.publicJwk);
}

async function registerProfile() {
  const result = await api("/api/register", {
    method: "POST",
    body: JSON.stringify({ userId: state.userId, publicKey: state.publicJwk })
  });
  mergeFriends(result.friends);
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
      return;
    }
    if (packet.type === "sent") {
      toast(`密文已交给中继：${packet.to}`);
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
    addMessage({ from: friend.userId, text: payload.text, burnAfter: payload.burnAfter, mine: false, status: "已解密" });
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
  const timer = setInterval(() => {
    const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    burning.textContent = `${left}s 后焚毁`;
    if (left <= 0) {
      clearInterval(timer);
      node.remove();
      if (!els.messages.children.length) {
        els.messages.innerHTML = `<p class="empty">消息已焚毁，本地不保留聊天记录。</p>`;
      }
    }
  }, 250);
}

function selectFriend(userId) {
  state.activeFriendId = userId;
  els.chatTitle.textContent = userId;
  const canSend = Boolean(state.userId && state.friends.get(userId));
  els.messageInput.disabled = !canSend;
  els.sendBtn.disabled = !canSend;
  renderFriends();
}

function renderFriends() {
  if (!state.friends.size) {
    els.friendList.innerHTML = `<p class="hint">暂无好友。用邀请代码添加一个联系人。</p>`;
    return;
  }
  els.friendList.innerHTML = "";
  for (const friend of state.friends.values()) {
    const row = document.createElement("div");
    row.className = `friend ${friend.userId === state.activeFriendId ? "active" : ""}`;
    row.innerHTML = `
      <span><strong>${escapeHtml(friend.userId)}</strong><small>公钥已保存</small></span>
      <button type="button">聊天</button>
    `;
    row.querySelector("button").addEventListener("click", () => selectFriend(friend.userId));
    els.friendList.append(row);
  }
}

async function resolveFriend() {
  const rawInvite = els.friendInvite.value.trim();
  const rawId = els.friendId.value.trim();
  if (rawInvite) return parseInvite(rawInvite);
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(rawId)) throw new Error("bad id");
  const result = await api(`/api/users/${encodeURIComponent(rawId)}`);
  return { userId: result.userId, publicKey: result.publicKey };
}

function makeInvite(userId, publicKey) {
  return btoaUnicode(JSON.stringify({ userId, publicKey }));
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
    if (friend?.userId && friend?.publicKey) state.friends.set(friend.userId, friend);
  }
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

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}
