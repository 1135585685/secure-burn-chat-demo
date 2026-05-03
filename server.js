import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, normalize } from "node:path";
import pg from "pg";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 8787);
const PUBLIC_DIR = join(process.cwd(), "public");
const DATA_FILE = process.env.DATA_FILE || join(process.cwd(), "data", "store.json");
const DATABASE_URL = process.env.DATABASE_URL || "";
const UPSTASH_REDIS_REST_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const UPSTASH_REDIS_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ADMIN_CAPTURE_MESSAGES = process.env.ADMIN_CAPTURE_MESSAGES === "true";
const clients = new Map();
const offlineQueues = new Map();
const OFFLINE_TTL_MS = 30 * 1000;
const MAX_OFFLINE_QUEUE_PER_USER = 20;
const MAX_FLOW_EVENTS = 300;
const MAX_MESSAGE_CAPTURES = 200;
let store = { users: {}, friends: {} };
let dbPool = null;
const flowEvents = [];
const messageCaptures = [];
const usePostgres = Boolean(DATABASE_URL);
const useUpstash = Boolean(UPSTASH_REDIS_REST_URL && UPSTASH_REDIS_REST_TOKEN);

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
      "cache-control": "no-store",
      ...securityHeaders(filePath)
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
      send(socket, { type: "ready", userId, friends: getFriends(userId), adminCaptureMessages: ADMIN_CAPTURE_MESSAGES });
      recordFlow("client.connected", { userId, onlineUsers: clients.size });
      broadcastPresence(userId);
      await flushOffline(userId);
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
      const delivery = await deliverOrQueue(sealed);
      captureMessage({ packet, sealed, delivery });
      recordFlow("message.accepted", { from, to, delivery, messageId: sealed.id });
      send(socket, { type: "sent", id: sealed.id, to, delivery });
    }
  });

  socket.on("close", () => {
    if (userId && clients.get(userId) === socket) clients.delete(userId);
    if (userId) recordFlow("client.disconnected", { userId, onlineUsers: clients.size });
    if (userId) broadcastPresence(userId);
  });
});

await initPersistence();

async function handleApi(req, res, url) {
  if (url.pathname.startsWith("/api/admin/")) {
    return handleAdminApi(req, res, url);
  }

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

async function handleAdminApi(req, res, url) {
  if (!isAdminAuthorized(req)) {
    return json(res, ADMIN_TOKEN ? 401 : 503, {
      ok: false,
      error: ADMIN_TOKEN ? "Admin token required" : "ADMIN_TOKEN is not configured"
    });
  }

  if (req.method === "GET" && url.pathname === "/api/admin/summary") {
    return json(res, 200, {
      ok: true,
      persistence: {
        users: usePostgres ? "postgres" : "file",
        offlineQueue: useUpstash ? "upstash" : "memory"
      },
      users: adminUsers(),
      friends: adminFriends(),
      offlineQueues: await adminOfflineQueues(),
      flowEvents,
      messageCaptures: ADMIN_CAPTURE_MESSAGES ? messageCaptures : [],
      captureMessages: ADMIN_CAPTURE_MESSAGES
    });
  }

  if (req.method === "GET" && url.pathname === "/api/admin/export") {
    return json(res, 200, {
      ok: true,
      store: sanitizedStore(),
      offlineQueues: await adminOfflineQueues(),
      flowEvents,
      messageCaptures: ADMIN_CAPTURE_MESSAGES ? messageCaptures : [],
      captureMessages: ADMIN_CAPTURE_MESSAGES
    });
  }

  if (req.method === "POST" && url.pathname === "/api/admin/users") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    if (!userId || !isPublicKey(body.publicKey)) return json(res, 400, { ok: false, error: "Invalid user" });
    await registerUser(userId, body.publicKey);
    recordFlow("admin.user.upsert", { userId });
    return json(res, 200, { ok: true, user: adminUsers().find((user) => user.userId === userId) });
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/admin/users/")) {
    const userId = sanitizeId(decodeURIComponent(url.pathname.split("/").pop() || ""));
    if (!userId) return json(res, 400, { ok: false, error: "Invalid user id" });
    await deleteUser(userId);
    recordFlow("admin.user.delete", { userId });
    return json(res, 200, { ok: true });
  }

  if (req.method === "POST" && url.pathname === "/api/admin/friends") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    const friendId = sanitizeId(body.friendId);
    if (!userId || !friendId || userId === friendId || !store.users[userId] || !store.users[friendId]) {
      return json(res, 400, { ok: false, error: "Invalid friend edge" });
    }
    await addFriend(userId, friendId);
    sendUser(userId, { type: "friends", friends: getFriends(userId) });
    recordFlow("admin.friend.add", { userId, friendId });
    return json(res, 200, { ok: true, friends: adminFriends() });
  }

  if (req.method === "DELETE" && url.pathname === "/api/admin/friends") {
    const body = await readJson(req);
    const userId = sanitizeId(body.userId);
    const friendId = sanitizeId(body.friendId);
    if (!userId || !friendId) return json(res, 400, { ok: false, error: "Invalid friend edge" });
    await removeFriend(userId, friendId);
    sendUser(userId, { type: "friends", friends: getFriends(userId) });
    recordFlow("admin.friend.delete", { userId, friendId });
    return json(res, 200, { ok: true, friends: adminFriends() });
  }

  if (req.method === "PUT" && url.pathname === "/api/admin/store") {
    const body = await readJson(req);
    if (!isValidAdminStore(body.store)) return json(res, 400, { ok: false, error: "Invalid store" });
    store = normalizeAdminStore(body.store);
    await saveStore();
    recordFlow("admin.store.replace", { users: Object.keys(store.users).length, edges: adminFriends().length });
    return json(res, 200, { ok: true, store: sanitizedStore() });
  }

  return json(res, 404, { ok: false, error: "Not found" });
}

async function initPersistence() {
  if (usePostgres) {
    dbPool = new pg.Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
    });
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        public_key JSONB NOT NULL,
        fingerprint TEXT NOT NULL,
        updated_at BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS friends (
        user_id TEXT NOT NULL,
        friend_id TEXT NOT NULL,
        PRIMARY KEY (user_id, friend_id)
      );
    `);
  }
  await loadStore();
}

async function loadStore() {
  if (usePostgres) {
    const users = await dbPool.query("SELECT user_id, public_key, fingerprint, updated_at FROM users");
    const friends = await dbPool.query("SELECT user_id, friend_id FROM friends");
    store = { users: {}, friends: {} };
    for (const row of users.rows) {
      store.users[row.user_id] = {
        publicKey: row.public_key,
        fingerprint: row.fingerprint,
        updatedAt: Number(row.updated_at)
      };
      store.friends[row.user_id] ||= [];
    }
    for (const row of friends.rows) {
      store.friends[row.user_id] ||= [];
      store.friends[row.user_id].push(row.friend_id);
    }
    for (const friendList of Object.values(store.friends)) friendList.sort();
    return;
  }

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
  if (usePostgres) {
    const client = await dbPool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM friends");
      await client.query("DELETE FROM users");
      for (const [userId, user] of Object.entries(store.users)) {
        await client.query(
          "INSERT INTO users (user_id, public_key, fingerprint, updated_at) VALUES ($1, $2, $3, $4)",
          [userId, user.publicKey, user.fingerprint || fingerprintPublicKey(user.publicKey), user.updatedAt || Date.now()]
        );
      }
      for (const [userId, friends] of Object.entries(store.friends)) {
        for (const friendId of friends) {
          await client.query(
            "INSERT INTO friends (user_id, friend_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            [userId, friendId]
          );
        }
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return;
  }

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
  recordFlow(keyChanged ? "user.key.changed" : "user.registered", { userId, fingerprint });
  if (keyChanged) {
    broadcastKeyChange(userId);
  }
}

async function addFriend(userId, friendId) {
  store.friends[userId] ||= [];
  if (!store.friends[userId].includes(friendId)) store.friends[userId].push(friendId);
  store.friends[userId].sort();
  await saveStore();
  recordFlow("friend.added", { userId, friendId, mutual: areMutualFriends(userId, friendId) });
}

async function removeFriend(userId, friendId) {
  store.friends[userId] = (store.friends[userId] || []).filter((id) => id !== friendId);
  await saveStore();
  recordFlow("friend.removed", { userId, friendId });
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
  recordFlow("user.deleted", { userId, affected: affected.size });
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
    "cache-control": "no-store",
    ...securityHeaders()
  });
  res.end(JSON.stringify(body));
}

function securityHeaders(filePath = "") {
  const connect = [
    "'self'",
    "ws:",
    "wss:",
    UPSTASH_REDIS_REST_URL ? new URL(UPSTASH_REDIS_REST_URL).origin : ""
  ].filter(Boolean).join(" ");

  return {
    "content-security-policy": [
      "default-src 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "script-src 'self'",
      "style-src 'self'",
      `connect-src ${connect}`,
      "img-src 'self' data:",
      "manifest-src 'self'",
      "worker-src 'self'"
    ].join("; "),
    "cross-origin-opener-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    ...(extname(filePath) === ".html" ? { "clear-site-data": '"cache"' } : {})
  };
}

async function deliverOrQueue(packet) {
  const target = clients.get(packet.to);
  if (target?.readyState === target.OPEN) {
    send(target, packet);
    recordFlow("message.delivered", { from: packet.from, to: packet.to, messageId: packet.id });
    return "delivered";
  }

  if (useUpstash) {
    const key = offlineQueueKey(packet.to);
    const current = Number(await redisCommand(["LLEN", key])) || 0;
    if (current >= MAX_OFFLINE_QUEUE_PER_USER) {
      sendUser(packet.from, { type: "expired", id: packet.id, to: packet.to, reason: "recipient queue full" });
      recordFlow("message.rejected", { from: packet.from, to: packet.to, messageId: packet.id, reason: "queue full" });
      return "rejected";
    }
    await redisPipeline([
      ["RPUSH", key, JSON.stringify(packet)],
      ["EXPIRE", key, String(Math.ceil(OFFLINE_TTL_MS / 1000))],
      ["LTRIM", key, String(-MAX_OFFLINE_QUEUE_PER_USER), "-1"]
    ]);
    setTimeout(async () => {
      const queued = await loadRedisQueue(packet.to);
      if (queued.some((item) => item.id === packet.id)) {
        await saveRedisQueue(packet.to, queued.filter((item) => item.id !== packet.id));
        sendUser(packet.from, { type: "expired", id: packet.id, to: packet.to, reason: "offline ttl expired" });
        recordFlow("message.expired", { from: packet.from, to: packet.to, messageId: packet.id, reason: "offline ttl expired" });
      }
    }, OFFLINE_TTL_MS).unref();
    recordFlow("message.queued", { from: packet.from, to: packet.to, messageId: packet.id, backend: "upstash" });
    return "queued";
  }

  const queue = offlineQueues.get(packet.to) || [];
  if (queue.length >= MAX_OFFLINE_QUEUE_PER_USER) {
    sendUser(packet.from, { type: "expired", id: packet.id, to: packet.to, reason: "recipient queue full" });
    recordFlow("message.rejected", { from: packet.from, to: packet.to, messageId: packet.id, reason: "queue full" });
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
      recordFlow("message.expired", { from: packet.from, to: packet.to, messageId: packet.id, reason: "offline ttl expired" });
    }
  }, OFFLINE_TTL_MS).unref();
  recordFlow("message.queued", { from: packet.from, to: packet.to, messageId: packet.id, backend: "memory" });
  return "queued";
}

async function flushOffline(userId) {
  if (useUpstash) {
    const queue = await loadRedisQueue(userId);
    if (!queue.length) return;
    await redisCommand(["DEL", offlineQueueKey(userId)]);
    for (const packet of queue) {
      if (Date.now() - packet.createdAt < OFFLINE_TTL_MS) {
      send(clients.get(userId), packet);
      sendUser(packet.from, { type: "delivered", id: packet.id, to: userId });
      recordFlow("message.delivered", { from: packet.from, to: userId, messageId: packet.id, fromQueue: true });
    } else {
      sendUser(packet.from, { type: "expired", id: packet.id, to: userId, reason: "offline ttl expired" });
      recordFlow("message.expired", { from: packet.from, to: userId, messageId: packet.id, reason: "offline ttl expired" });
    }
    }
    return;
  }

  const queue = offlineQueues.get(userId);
  if (!queue?.length) return;
  offlineQueues.delete(userId);
  for (const packet of queue) {
    if (Date.now() - packet.createdAt < OFFLINE_TTL_MS) {
      send(clients.get(userId), packet);
      sendUser(packet.from, { type: "delivered", id: packet.id, to: userId });
      recordFlow("message.delivered", { from: packet.from, to: userId, messageId: packet.id, fromQueue: true });
    }
  }
}

function send(socket, packet) {
  if (socket && socket.readyState === socket.OPEN) socket.send(JSON.stringify(packet));
}

function sendUser(userId, packet) {
  send(clients.get(userId), packet);
}

async function redisCommand(command) {
  const response = await fetch(`${UPSTASH_REDIS_REST_URL}/pipeline`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
      "content-type": "application/json"
    },
    body: JSON.stringify([command])
  });
  const body = await response.json();
  if (!response.ok || body[0]?.error) throw new Error(body[0]?.error || "Redis command failed");
  return body[0]?.result;
}

async function redisPipeline(commands) {
  const response = await fetch(`${UPSTASH_REDIS_REST_URL}/pipeline`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(commands)
  });
  const body = await response.json();
  if (!response.ok || body.some((item) => item.error)) throw new Error("Redis pipeline failed");
  return body.map((item) => item.result);
}

async function loadRedisQueue(userId) {
  const entries = await redisCommand(["LRANGE", offlineQueueKey(userId), "0", "-1"]);
  return (entries || []).map((entry) => JSON.parse(entry));
}

async function saveRedisQueue(userId, queue) {
  const key = offlineQueueKey(userId);
  if (!queue.length) {
    await redisCommand(["DEL", key]);
    return;
  }
  await redisPipeline([
    ["DEL", key],
    ["RPUSH", key, ...queue.map((packet) => JSON.stringify(packet))],
    ["EXPIRE", key, String(Math.ceil(OFFLINE_TTL_MS / 1000))]
  ]);
}

function offlineQueueKey(userId) {
  return `secure-burn:offline:${userId}`;
}

function isAdminAuthorized(req) {
  if (!ADMIN_TOKEN) return false;
  const auth = req.headers.authorization || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  return bearer === ADMIN_TOKEN || req.headers["x-admin-token"] === ADMIN_TOKEN;
}

function adminUsers() {
  return Object.entries(store.users)
    .map(([userId, user]) => ({
      userId,
      fingerprint: user.fingerprint || fingerprintPublicKey(user.publicKey),
      publicKey: user.publicKey,
      updatedAt: user.updatedAt || null,
      online: isOnline(userId),
      friendCount: (store.friends[userId] || []).length
    }))
    .sort((a, b) => a.userId.localeCompare(b.userId));
}

function adminFriends() {
  return Object.entries(store.friends)
    .flatMap(([userId, friends]) => friends.map((friendId) => ({
      userId,
      friendId,
      mutual: areMutualFriends(userId, friendId)
    })))
    .sort((a, b) => `${a.userId}:${a.friendId}`.localeCompare(`${b.userId}:${b.friendId}`));
}

async function adminOfflineQueues() {
  const userIds = Object.keys(store.users).sort();
  const summaries = [];
  for (const userId of userIds) {
    if (useUpstash) {
      const count = Number(await redisCommand(["LLEN", offlineQueueKey(userId)])) || 0;
      if (count) summaries.push({ userId, count, backend: "upstash", ttlSeconds: Math.ceil(OFFLINE_TTL_MS / 1000) });
      continue;
    }
    const queue = offlineQueues.get(userId) || [];
    if (!queue.length) continue;
    summaries.push({
      userId,
      count: queue.length,
      backend: "memory",
      ttlSeconds: Math.ceil(OFFLINE_TTL_MS / 1000),
      oldestAt: Math.min(...queue.map((packet) => packet.createdAt)),
      newestAt: Math.max(...queue.map((packet) => packet.createdAt))
    });
  }
  return summaries;
}

function sanitizedStore() {
  return {
    users: Object.fromEntries(adminUsers().map((user) => [user.userId, {
      publicKey: user.publicKey,
      fingerprint: user.fingerprint,
      updatedAt: user.updatedAt
    }])),
    friends: Object.fromEntries(Object.entries(store.friends).map(([userId, friends]) => [userId, [...friends].sort()]))
  };
}

function isValidAdminStore(candidate) {
  if (!candidate || typeof candidate !== "object" || !candidate.users || !candidate.friends) return false;
  for (const [userId, user] of Object.entries(candidate.users)) {
    if (!sanitizeId(userId) || !isPublicKey(user.publicKey)) return false;
  }
  for (const [userId, friends] of Object.entries(candidate.friends)) {
    if (!sanitizeId(userId) || !Array.isArray(friends)) return false;
    for (const friendId of friends) {
      if (!sanitizeId(friendId) || !candidate.users[friendId]) return false;
    }
  }
  return true;
}

function normalizeAdminStore(candidate) {
  const next = { users: {}, friends: {} };
  for (const [userId, user] of Object.entries(candidate.users)) {
    next.users[userId] = {
      publicKey: user.publicKey,
      fingerprint: user.fingerprint || fingerprintPublicKey(user.publicKey),
      updatedAt: Number(user.updatedAt || Date.now())
    };
    next.friends[userId] = [];
  }
  for (const [userId, friends] of Object.entries(candidate.friends)) {
    next.friends[userId] = [...new Set(friends)].sort();
  }
  return next;
}

function recordFlow(type, details = {}) {
  flowEvents.push({
    id: crypto.randomUUID(),
    at: Date.now(),
    type,
    details
  });
  while (flowEvents.length > MAX_FLOW_EVENTS) flowEvents.shift();
}

function captureMessage({ packet, sealed, delivery }) {
  if (!ADMIN_CAPTURE_MESSAGES) return;
  messageCaptures.push({
    id: sealed.id,
    at: sealed.createdAt,
    from: sealed.from,
    to: sealed.to,
    delivery,
    encrypted: packet.encrypted,
    debugPlaintext: typeof packet.debugPlaintext === "string" ? packet.debugPlaintext : null
  });
  while (messageCaptures.length > MAX_MESSAGE_CAPTURES) messageCaptures.shift();
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
