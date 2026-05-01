const els = {
  userId: document.querySelector("#userId"),
  startBtn: document.querySelector("#startBtn"),
  connectionState: document.querySelector("#connectionState"),
  inviteCode: document.querySelector("#inviteCode"),
  copyInviteBtn: document.querySelector("#copyInviteBtn"),
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

  await loadOrCreateIdentity(userId);
  restoreFriends(userId);
  renderFriends();
  connect(userId);
});

els.copyInviteBtn.addEventListener("click", async () => {
  if (!els.inviteCode.value) return;
  await navigator.clipboard.writeText(els.inviteCode.value);
  toast("邀请代码已复制。");
});

els.addFriendBtn.addEventListener("click", async () => {
  try {
    const invite = parseInvite(els.friendInvite.value.trim());
    if (!invite.userId || !invite.publicKey) throw new Error("bad invite");
    if (invite.userId === state.userId) return toast("不能添加自己。");
    if (!state.userId) return toast("请先输入你的 ID 并进入。");
    state.friends.set(invite.userId, invite);
    saveFriends();
    renderFriends();
    els.friendInvite.value = "";
    selectFriend(invite.userId);
  } catch {
    toast("邀请代码无法识别。");
  }
});

els.messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = els.messageInput.value.trim();
  if (!text || !state.activeFriendId || !state.socket) return;
  const friend = state.friends.get(state.activeFriendId);
  const burnAfter = Number(els.burnAfter.value);
  const encrypted = await encryptForFriend(friend, { text, burnAfter, sentAt: Date.now() });
  state.socket.send(JSON.stringify({
    type: "message",
    from: state.userId,
    to: friend.userId,
    encrypted
  }));
  addMessage({ from: state.userId, text, burnAfter, mine: true });
  els.messageInput.value = "";
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

function connect(userId) {
  state.socket?.close();
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  state.socket = new WebSocket(`${protocol}://${location.host}`);
  els.connectionState.textContent = "正在连接...";

  state.socket.addEventListener("open", () => {
    state.socket.send(JSON.stringify({ type: "hello", userId }));
  });

  state.socket.addEventListener("message", async (event) => {
    const packet = JSON.parse(event.data);
    if (packet.type === "ready") {
      els.connectionState.textContent = `已连接：${packet.userId}`;
      els.securityStatus.textContent = "端到端加密已启用";
      return;
    }
    if (packet.type === "message") {
      await handleEncryptedMessage(packet);
    }
  });

  state.socket.addEventListener("close", () => {
    els.connectionState.textContent = "连接已断开";
    els.securityStatus.textContent = "等待重新连接";
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
    addMessage({ from: friend.userId, text: payload.text, burnAfter: payload.burnAfter, mine: false });
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

function addMessage({ from, text, burnAfter, mine }) {
  if (els.messages.querySelector(".empty")) els.messages.innerHTML = "";
  const node = document.createElement("article");
  node.className = `message ${mine ? "mine" : ""}`;
  node.innerHTML = `
    <div></div>
    <p class="meta"><span class="burning"></span> · ${escapeHtml(from)}</p>
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
  els.messageInput.disabled = false;
  els.sendBtn.disabled = false;
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
    row.innerHTML = `<strong>${escapeHtml(friend.userId)}</strong><button type="button">聊天</button>`;
    row.querySelector("button").addEventListener("click", () => selectFriend(friend.userId));
    els.friendList.append(row);
  }
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
