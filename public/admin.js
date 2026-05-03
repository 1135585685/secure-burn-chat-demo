const els = {
  tokenForm: document.querySelector("#tokenForm"),
  adminToken: document.querySelector("#adminToken"),
  adminStatus: document.querySelector("#adminStatus"),
  refreshBtn: document.querySelector("#refreshBtn"),
  userCount: document.querySelector("#userCount"),
  edgeCount: document.querySelector("#edgeCount"),
  onlineCount: document.querySelector("#onlineCount"),
  queueCount: document.querySelector("#queueCount"),
  usersTable: document.querySelector("#usersTable"),
  edgesTable: document.querySelector("#edgesTable"),
  friendForm: document.querySelector("#friendForm"),
  edgeUser: document.querySelector("#edgeUser"),
  edgeFriend: document.querySelector("#edgeFriend"),
  flowGraph: document.querySelector("#flowGraph"),
  flowEvents: document.querySelector("#flowEvents"),
  captureWarning: document.querySelector("#captureWarning"),
  messageCaptures: document.querySelector("#messageCaptures"),
  storeEditor: document.querySelector("#storeEditor"),
  saveStoreBtn: document.querySelector("#saveStoreBtn")
};

let token = localStorage.getItem("secureBurnAdminToken") || "";
let snapshot = null;
els.adminToken.value = token;

els.tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  token = els.adminToken.value.trim();
  localStorage.setItem("secureBurnAdminToken", token);
  await refresh();
});

els.refreshBtn.addEventListener("click", refresh);

els.friendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const action = event.submitter?.dataset.action;
  const body = { userId: els.edgeUser.value.trim(), friendId: els.edgeFriend.value.trim() };
  await adminFetch("/api/admin/friends", {
    method: action === "delete" ? "DELETE" : "POST",
    body: JSON.stringify(body)
  });
  els.edgeUser.value = "";
  els.edgeFriend.value = "";
  await refresh();
});

els.saveStoreBtn.addEventListener("click", async () => {
  const confirmed = window.confirm("这会替换服务器用户和好友关系存储。确认继续？");
  if (!confirmed) return;
  const store = JSON.parse(els.storeEditor.value);
  await adminFetch("/api/admin/store", {
    method: "PUT",
    body: JSON.stringify({ store })
  });
  await refresh();
});

async function refresh() {
  try {
    snapshot = await adminFetch("/api/admin/summary");
    const exported = await adminFetch("/api/admin/export");
    render(snapshot, exported.store);
    status(`已连接。用户存储：${snapshot.persistence.users}，离线队列：${snapshot.persistence.offlineQueue}`);
  } catch (error) {
    status(error.message);
  }
}

function render(data, store) {
  els.userCount.textContent = data.users.length;
  els.edgeCount.textContent = data.friends.length;
  els.onlineCount.textContent = data.users.filter((user) => user.online).length;
  els.queueCount.textContent = data.offlineQueues.reduce((sum, queue) => sum + queue.count, 0);
  renderUsers(data.users);
  renderEdges(data.friends);
  renderFlow(data.flowEvents);
  renderCaptures(data.captureMessages, data.messageCaptures || []);
  els.storeEditor.value = JSON.stringify(store, null, 2);
}

function renderUsers(users) {
  els.usersTable.innerHTML = users.map((user) => `
    <div class="row">
      <div>
        <strong>${escapeHtml(user.userId)}</strong>
        <code>${escapeHtml(user.fingerprint)}</code>
        <small>${user.online ? "在线" : "离线"} · 好友 ${user.friendCount} · ${formatTime(user.updatedAt)}</small>
      </div>
      <button class="danger" data-delete-user="${escapeHtml(user.userId)}">删除</button>
    </div>
  `).join("") || `<p class="status">暂无用户。</p>`;

  els.usersTable.querySelectorAll("[data-delete-user]").forEach((button) => {
    button.addEventListener("click", async () => {
      const userId = button.dataset.deleteUser;
      if (!window.confirm(`删除用户 ${userId}？`)) return;
      await adminFetch(`/api/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
      await refresh();
    });
  });
}

function renderEdges(edges) {
  els.edgesTable.innerHTML = edges.map((edge) => `
    <div class="row">
      <div>
        <strong>${escapeHtml(edge.userId)} -> ${escapeHtml(edge.friendId)}</strong>
        <small>${edge.mutual ? "双向确认" : "单向"}</small>
      </div>
      <button class="danger" data-user="${escapeHtml(edge.userId)}" data-friend="${escapeHtml(edge.friendId)}">删除</button>
    </div>
  `).join("") || `<p class="status">暂无好友关系。</p>`;

  els.edgesTable.querySelectorAll("[data-user]").forEach((button) => {
    button.addEventListener("click", async () => {
      await adminFetch("/api/admin/friends", {
        method: "DELETE",
        body: JSON.stringify({ userId: button.dataset.user, friendId: button.dataset.friend })
      });
      await refresh();
    });
  });
}

function renderFlow(events) {
  const recent = [...events].slice(-80);
  const nodes = buildFlowNodes(recent);
  els.flowGraph.innerHTML = flowSvg(nodes, recent);
  els.flowEvents.innerHTML = recent.slice().reverse().map((event) => `
    <div class="event">
      <span>${formatTime(event.at)}</span>
      <strong>${escapeHtml(event.type)}</strong>
      <code>${escapeHtml(JSON.stringify(event.details))}</code>
    </div>
  `).join("") || `<p class="status">暂无数据流事件。</p>`;
}

function renderCaptures(enabled, captures) {
  els.captureWarning.textContent = enabled
    ? "测试模式已开启：后台正在保存并展示消息明文副本与密文 body。不要在生产环境开启。"
    : "测试模式未开启。若必须调试消息内容，请在服务端设置 ADMIN_CAPTURE_MESSAGES=true 后重启。";

  if (!enabled) {
    els.messageCaptures.innerHTML = "";
    return;
  }

  els.messageCaptures.innerHTML = captures.slice().reverse().map((capture) => `
    <article class="capture">
      <header>
        <strong>${escapeHtml(capture.from)} -> ${escapeHtml(capture.to)}</strong>
        <span>${escapeHtml(capture.delivery)} · ${formatTime(capture.at)}</span>
      </header>
      <label>明文副本</label>
      <pre>${escapeHtml(capture.debugPlaintext ?? "(未随消息提交明文副本)")}</pre>
      <label>密文 body</label>
      <pre>${escapeHtml(JSON.stringify(capture.encrypted, null, 2))}</pre>
    </article>
  `).join("") || `<p class="status">暂无捕获消息。</p>`;
}

function buildFlowNodes(events) {
  const ids = new Set(["server"]);
  for (const event of events) {
    if (event.details?.userId) ids.add(event.details.userId);
    if (event.details?.from) ids.add(event.details.from);
    if (event.details?.to) ids.add(event.details.to);
    if (event.details?.friendId) ids.add(event.details.friendId);
  }
  return [...ids];
}

function flowSvg(nodes, events) {
  const width = 960;
  const height = 260;
  const cx = width / 2;
  const cy = height / 2;
  const radius = 92;
  const positions = new Map(nodes.map((id, index) => {
    if (id === "server") return [id, { x: cx, y: cy }];
    const angle = (Math.PI * 2 * index) / Math.max(1, nodes.length - 1);
    return [id, { x: cx + Math.cos(angle) * radius * 2.6, y: cy + Math.sin(angle) * radius }];
  }));

  const lines = events.slice(-40).map((event) => {
    const from = event.details?.from || event.details?.userId || "server";
    const to = event.details?.to || event.details?.friendId || "server";
    const a = positions.get(from) || positions.get("server");
    const b = positions.get(to) || positions.get("server");
    const color = event.type.includes("expired") || event.type.includes("delete") ? "#b7372f" : event.type.includes("queued") ? "#a85d31" : "#12715b";
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${color}" stroke-width="1.5" opacity="0.36" />`;
  }).join("");

  const circles = nodes.map((id) => {
    const p = positions.get(id);
    const server = id === "server";
    return `
      <circle cx="${p.x}" cy="${p.y}" r="${server ? 28 : 20}" fill="${server ? "#12715b" : "#fff"}" stroke="#12715b" stroke-width="2" />
      <text x="${p.x}" y="${p.y + 42}" text-anchor="middle" font-size="12" fill="#14211c">${escapeHtml(id)}</text>
    `;
  }).join("");

  return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="数据流可视化">${lines}${circles}</svg>`;
}

async function adminFetch(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "authorization": `Bearer ${token}`,
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ok === false) throw new Error(body.error || "请求失败");
  return body;
}

function status(message) {
  els.adminStatus.textContent = message;
}

function formatTime(value) {
  if (!value) return "未知时间";
  return new Date(value).toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

if (token) refresh();
