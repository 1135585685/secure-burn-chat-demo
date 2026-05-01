import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, normalize } from "node:path";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 8787);
const PUBLIC_DIR = join(process.cwd(), "public");
const DATA_FILE = process.env.DATA_FILE || join(process.cwd(), "data", "store.json");
const clients = new Map();
const offlineQueues = new Map();
const OFFLINE_TTL_MS = 30 * 1000;
const MAX_OFFLINE_QUEUE_PER_USER = 20;
let store = { users: {}, friends: {} };

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    if (url.pathname.startsWith("/api/")) {
      return handleApi(req, res, url);
    }

    const requested = url.pathname === "/" ? "/index.html" : url.pathname;
    const safePath = normalize(requested).replace(/^(\.\.[/\\])+/, "");
    const filePath = join(PUBLIC_DIR, safePath);
    const body = await readFile(filePath);
    res.writeHead(200, {
      "content-type": contentTypes[extname(filePath)] || "application/octet-stream",
      "cache-control": "no-store"
    });
    res.end(body);
  } catch {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
});

const wss = new WebSocketServer({ server });

wss.on("connection", (socket) => {
  let userId = null;

  socket.on("message", async (raw) => {
    let packet;
    try {
      packet = JSON.parse(raw.toString());
    } catch {
      return send(socket, { type: "error", message: "Invalid JSON" });
    }

    if (packet.type === "hello") {
      userId = sanitizeId(packet.userId);
      if (!userId) return send(socket, { type: "error", message: "Invalid user id" });
      if (isPublicKey(packet.publicKey)) {
        await registerUser(userId, packet.publicKey);
      }
      clients.set(userId, socket);
      send(socket, { type: "ready", userId, friends: getFriends(userId) });
      broadcastPresence(userId);
      flushOffline(userId);
      return;
    }

    if (packet.type === "message") {
      const from = sanitizeId(packet.from);
      const to = sanitizeId(packet.to);
      if (!from || !to || from !== userId || !packet.encrypted) return;
      if (!areMutualFriends(from, to)) {
        return send(socket, { type: "error", message: "消息未发送：需要双方互相添加好友。" });
      }
      if (!isOnline(to)) {
        return send(socket, { type: "error", message: "消息未发送：好友当前不在线。" });
      }

      const sealed = {
        type: "message",
        id: crypto.randomUUID(),
        from,
        to,
        encrypted: packet.encrypted,
        createdAt: Date.now()
      };
      const delivery = deliverOrQueue(sealed);
      send(socket, { type: "sent", id: sealed.id, to, delivery });
    }
  });

  socket.on("close", () => {
    if (userId && clients.get(userId) === socket) clients.delete(userId);
    if (userId) broadcastPresence(userId);
  });
});

await loadStore();

async function handleApi(req, res, url) {
  if (req.method === "POST" && url.pathname === "/api/register") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    if (!userId || !isPublicKey(body.publicKey)) {
      return json(res, 400, { ok: false, error: "Invalid user id or public key" });
    }
    await registerUser(userId, body.publicKey);
    return json(res, 200, { ok: true, userId, friends: getFriends(userId) });
  }

  if (req.method === "DELETE" && url.pathname === "/api/users") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    if (!userId) return json(res, 400, { ok: false, error: "Invalid user id" });
    await deleteUser(userId);
    sendUser(userId, { type: "accountDeleted" });
    const socket = clients.get(userId);
    if (socket) socket.close(1000, "account deleted");
    return json(res, 200, { ok: true });
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/users/")) {
    const userId = sanitizeId(decodeURIComponent(url.pathname.split("/").pop() || ""));
    const user = userId ? store.users[userId] : null;
    if (!user) return json(res, 404, { ok: false, error: "User not found" });
    return json(res, 200, { ok: true, userId, publicKey: user.publicKey, fingerprint: user.fingerprint || fingerprintPublicKey(user.publicKey) });
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/friends/")) {
    const userId = sanitizeId(decodeURIComponent(url.pathname.split("/").pop() || ""));
    if (!userId) return json(res, 400, { ok: false, error: "Invalid user id" });
    return json(res, 200, { ok: true, friends: getFriends(userId) });
  }

  if (req.method === "DELETE" && url.pathname === "/api/friends") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    const friendId = sanitizeId(body.friendId);
    if (!userId || !friendId) return json(res, 400, { ok: false, error: "Invalid friend" });
    await removeFriend(userId, friendId);
    sendUser(friendId, { type: "friends", friends: getFriends(friendId) });
    sendUser(userId, { type: "friends", friends: getFriends(userId) });
    return json(res, 200, { ok: true, friends: getFriends(userId) });
  }

  if (req.method === "POST" && url.pathname === "/api/friends") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    const friendId = sanitizeId(body.friend?.userId || body.friendId);
    const publicKey = body.friend?.publicKey || store.users[friendId]?.publicKey;
    if (!userId || !friendId || userId === friendId || !isPublicKey(publicKey)) {
      return json(res, 400, { ok: false, error: "Invalid friend" });
    }
    await registerUser(friendId, publicKey);
    await addFriend(userId, friendId);
    sendUser(friendId, { type: "friends", friends: getFriends(friendId) });
    return json(res, 200, { ok: true, friends: getFriends(userId) });
  }

  return json(res, 404, { ok: false, error: "Not found" });
}

async function loadStore() {
  try {
    store = JSON.parse(await readFile(DATA_FILE, "utf8"));
    store.users ||= {};
    store.friends ||= {};
  } catch {
    store = { users: {}, friends: {} };
    await saveStore();
  }
}

async function saveStore() {
  await mkdir(dirname(DATA_FILE), { recursive: true });
  await writeFile(DATA_FILE, JSON.stringify(store, null, 2));
}

async function registerUser(userId, publicKey) {
  const fingerprint = fingerprintPublicKey(publicKey);
  const previous = store.users[userId];
  const keyChanged = Boolean(previous?.fingerprint && previous.fingerprint !== fingerprint);
  store.users[userId] = { publicKey, fingerprint, updatedAt: Date.now() };
  store.friends[userId] ||= [];
  await saveStore();
  if (keyChanged) {
    broadcastKeyChange(userId);
  }
}

async function addFriend(userId, friendId) {
  store.friends[userId] ||= [];
  if (!store.friends[userId].includes(friendId)) store.friends[userId].push(friendId);
  store.friends[userId].sort();
  await saveStore();
}

async function removeFriend(userId, friendId) {
  store.friends[userId] = (store.friends[userId] || []).filter((id) => id !== friendId);
  await saveStore();
}

async function deleteUser(userId) {
  const affected = new Set([
    ...(store.friends[userId] || []),
    ...Object.entries(store.friends)
      .filter(([, friends]) => friends.includes(userId))
      .map(([id]) => id)
  ]);
  delete store.users[userId];
  delete store.friends[userId];
  for (const id of Object.keys(store.friends)) {
    store.friends[id] = store.friends[id].filter((friendId) => friendId !== userId);
  }
  offlineQueues.delete(userId);
  await saveStore();
  for (const id of affected) {
    sendUser(id, { type: "friends", friends: getFriends(id) });
  }
}

function getFriends(userId) {
  return (store.friends[userId] || [])
    .map((friendId) => store.users[friendId] ? {
      userId: friendId,
      publicKey: store.users[friendId].publicKey,
      fingerprint: store.users[friendId].fingerprint || fingerprintPublicKey(store.users[friendId].publicKey),
      confirmed: areMutualFriends(userId, friendId),
      online: areMutualFriends(userId, friendId) && isOnline(friendId)
    } : null)
    .filter(Boolean);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 128) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function json(res, status, body) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(JSON.stringify(body));
}

function deliverOrQueue(packet) {
  const target = clients.get(packet.to);
  if (target?.readyState === target.OPEN) {
    send(target, packet);
    return "delivered";
  }

  const queue = offlineQueues.get(packet.to) || [];
  if (queue.length >= MAX_OFFLINE_QUEUE_PER_USER) {
    sendUser(packet.from, { type: "expired", id: packet.id, to: packet.to, reason: "recipient queue full" });
    return "rejected";
  }
  queue.push(packet);
  offlineQueues.set(packet.to, queue);
  setTimeout(() => {
    const existing = offlineQueues.get(packet.to) || [];
    const filtered = existing.filter((item) => item.id !== packet.id);
    if (filtered.length) offlineQueues.set(packet.to, filtered);
    else offlineQueues.delete(packet.to);
    if (existing.length !== filtered.length) {
      sendUser(packet.from, { type: "expired", id: packet.id, to: packet.to, reason: "offline ttl expired" });
    }
  }, OFFLINE_TTL_MS).unref();
  return "queued";
}

function flushOffline(userId) {
  const queue = offlineQueues.get(userId);
  if (!queue?.length) return;
  offlineQueues.delete(userId);
  for (const packet of queue) {
    if (Date.now() - packet.createdAt < OFFLINE_TTL_MS) {
      send(clients.get(userId), packet);
      sendUser(packet.from, { type: "delivered", id: packet.id, to: userId });
    }
  }
}

function send(socket, packet) {
  if (socket && socket.readyState === socket.OPEN) socket.send(JSON.stringify(packet));
}

function sendUser(userId, packet) {
  send(clients.get(userId), packet);
}

function isOnline(userId) {
  const socket = clients.get(userId);
  return Boolean(socket && socket.readyState === socket.OPEN);
}

function areMutualFriends(a, b) {
  return Boolean((store.friends[a] || []).includes(b) && (store.friends[b] || []).includes(a));
}

function broadcastPresence(changedUserId) {
  const visibleTo = new Set([
    ...(store.friends[changedUserId] || []),
    ...Object.entries(store.friends)
      .filter(([, friends]) => friends.includes(changedUserId))
      .map(([userId]) => userId)
  ]);
  for (const userId of visibleTo) {
    sendUser(userId, { type: "friends", friends: getFriends(userId) });
  }
}

function broadcastKeyChange(changedUserId) {
  const affected = new Set([
    ...(store.friends[changedUserId] || []),
    ...Object.entries(store.friends)
      .filter(([, friends]) => friends.includes(changedUserId))
      .map(([userId]) => userId)
  ]);
  for (const userId of affected) {
    sendUser(userId, {
      type: "keyChanged",
      userId: changedUserId,
      friends: getFriends(userId)
    });
  }
}

function sanitizeId(value) {
  if (typeof value !== "string") return "";
  const clean = value.trim();
  return /^[a-zA-Z0-9_-]{3,32}$/.test(clean) ? clean : "";
}

function isPublicKey(value) {
  const coord = /^[A-Za-z0-9_-]{40,48}$/;
  return Boolean(
    value &&
    value.kty === "EC" &&
    value.crv === "P-256" &&
    coord.test(value.x || "") &&
    coord.test(value.y || "")
  );
}

function fingerprintPublicKey(publicKey) {
  return createHash("sha256").update(canonicalJson(publicKey)).digest("hex").match(/.{1,4}/g).slice(0, 8).join(" ");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

server.listen(PORT, () => {
  console.log(`Secure Burn Chat demo running at http://localhost:${PORT}`);
});
