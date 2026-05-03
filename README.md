# Secure Burn Chat Demo

一个轻量网页通信 Demo，重点演示：

- 浏览器端生成 ECDH P-256 密钥
- 身份私钥保存为 IndexedDB 中不可导出的 WebCrypto `CryptoKey`
- 身份公钥指纹校验和密钥变更提醒
- 消息在浏览器内用 AES-GCM 加密
- Node 服务端只做 WebSocket 中继
- 服务端不保存明文消息
- 服务端持久保存用户公钥和好友关系
- 离线密文只存内存，最多 20 条，30 秒后过期，并返回投递/过期回执
- 可选 `DATABASE_URL` 使用 Supabase/PostgreSQL 保存用户、公钥和好友关系
- 可选 `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` 使用 Upstash Redis 保存短期离线密文队列
- CSP、SRI、PWA 固定版本缓存和安全响应头
- 受 `ADMIN_TOKEN` 保护的后台管理页 `/admin.html`
- 后台可管理用户、公钥、好友关系、服务器存储 JSON，并查看不含消息内容的数据流事件图
- 单轮次消息窗口：同一方连续消息会保留；对方发出下一条后，上一方消息消失；最后一条消息 15 分钟后消失
- 通过好友 ID 或邀请代码添加好友
- 双方互相添加且好友在线后，才允许发送消息
- 好友可以删除
- 支持退出当前会话
- 支持删除所有记录：清除本机身份密钥、好友缓存、当前消息，并请求服务端删除用户资料和好友关系

## 运行

```bash
npm install
npm start
```

打开：

```text
http://localhost:8787
```

## 试用方式

1. 打开两个浏览器窗口。
2. 第一个窗口用 `alice` 进入，复制邀请代码。
3. 第二个窗口用 `bob` 进入。
4. 双方可以输入对方 ID 添加好友，也可以互相粘贴邀请代码添加好友。
5. 双方都添加后，好友状态会变成在线可发送。
6. 选择好友后发送消息；你的消息会在对方下一条消息到来后消失，窗口内最后一条消息 15 分钟后消失。

好友关系会写入本地服务端的 `data/store.json`，这个文件不会提交到 Git。部署到 Render 免费实例时，实例重启或重新部署可能丢失本地文件；生产版本应改用 PostgreSQL、Redis 或 Render Disk 保存用户公钥和好友关系。

## 云端持久化

Render 环境变量：

```text
ADMIN_TOKEN=choose-a-long-random-secret
DATABASE_URL=postgresql://...
UPSTASH_REDIS_REST_URL=https://...
UPSTASH_REDIS_REST_TOKEN=...
```

没有这些变量时，Demo 会继续使用本地 `data/store.json` 和内存离线队列。

## 后台管理

打开：

```text
https://你的域名/admin.html
```

输入 `ADMIN_TOKEN` 后可以查看和管理：

- 用户、公钥、身份指纹、在线状态
- 好友关系边
- 当前离线队列数量
- 服务器存储 JSON
- 数据流可视化事件

后台不会展示消息明文，也不会展示密文 body。数据流事件只记录类型、用户 ID、好友 ID、投递状态、队列状态等元数据。

## 安全说明

这是原型 Demo，不是生产级安全产品。当前版本已经把身份私钥迁移到 IndexedDB 中的不可导出 `CryptoKey`，但网页端仍然无法防止恶意浏览器扩展、被篡改的前端代码、截图、调试器和被攻破设备。

生产版本建议升级：

- 原生 App 使用 iOS Keychain / Android Keystore
- 接入官方 Signal `libsignal`，替换当前 Demo 的简单 ECDH 会话密钥。官方 libsignal 暴露 Java、Swift、TypeScript API，但完整浏览器端集成需要打包和协议存储层，不应手写冒充。
- 做完整安全审计
