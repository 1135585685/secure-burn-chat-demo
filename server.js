import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 8787);
const PUBLIC_DIR = join(process.cwd(), "public");
const clients = new Map();
const offlineQueues = new Map();
const OFFLINE_TTL_MS = 60 * 1000;

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

  socket.on("message", (raw) => {
    let packet;
    try {
      packet = JSON.parse(raw.toString());
    } catch {
      return send(socket, { type: "error", message: "Invalid JSON" });
    }

    if (packet.type === "hello") {
      userId = sanitizeId(packet.userId);
      if (!userId) return send(socket, { type: "error", message: "Invalid user id" });
      clients.set(userId, socket);
      send(socket, { type: "ready", userId });
      flushOffline(userId);
      return;
    }

    if (packet.type === "message") {
      const from = sanitizeId(packet.from);
      const to = sanitizeId(packet.to);
      if (!from || !to || from !== userId || !packet.encrypted) return;

      const sealed = {
        type: "message",
        id: crypto.randomUUID(),
        from,
        to,
        encrypted: packet.encrypted,
        createdAt: Date.now()
      };
      deliverOrQueue(sealed);
      send(socket, { type: "sent", id: sealed.id, to });
    }
  });

  socket.on("close", () => {
    if (userId && clients.get(userId) === socket) clients.delete(userId);
  });
});

function deliverOrQueue(packet) {
  const target = clients.get(packet.to);
  if (target?.readyState === target.OPEN) {
    send(target, packet);
    return;
  }

  const queue = offlineQueues.get(packet.to) || [];
  queue.push(packet);
  offlineQueues.set(packet.to, queue);
  setTimeout(() => {
    const existing = offlineQueues.get(packet.to) || [];
    const filtered = existing.filter((item) => item.id !== packet.id);
    if (filtered.length) offlineQueues.set(packet.to, filtered);
    else offlineQueues.delete(packet.to);
  }, OFFLINE_TTL_MS).unref();
}

function flushOffline(userId) {
  const queue = offlineQueues.get(userId);
  if (!queue?.length) return;
  offlineQueues.delete(userId);
  for (const packet of queue) {
    if (Date.now() - packet.createdAt < OFFLINE_TTL_MS) send(clients.get(userId), packet);
  }
}

function send(socket, packet) {
  if (socket?.readyState === socket.OPEN) socket.send(JSON.stringify(packet));
}

function sanitizeId(value) {
  if (typeof value !== "string") return "";
  const clean = value.trim();
  return /^[a-zA-Z0-9_-]{3,32}$/.test(clean) ? clean : "";
}

server.listen(PORT, () => {
  console.log(`Secure Burn Chat demo running at http://localhost:${PORT}`);
});
