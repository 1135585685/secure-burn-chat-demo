# Secure Burn Chat Demo

一个轻量网页通信 Demo，重点演示：

- 浏览器端生成 ECDH P-256 密钥
- 消息在浏览器内用 AES-GCM 加密
- Node 服务端只做 WebSocket 中继
- 服务端不保存明文消息
- 服务端持久保存用户公钥和好友关系
- 离线密文只存内存，并在 60 秒后过期
- 消息显示后倒计时焚毁，本地不保留聊天记录
- 通过好友 ID 或邀请代码添加好友

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
5. 选择好友后发送消息，消息会自动倒计时焚毁。

好友关系会写入本地服务端的 `data/store.json`，这个文件不会提交到 Git。部署到 Render 免费实例时，实例重启或重新部署可能丢失本地文件；生产版本应改用 PostgreSQL、Redis 或 Render Disk 保存用户公钥和好友关系。

## 安全说明

这是原型 Demo，不是生产级安全产品。当前版本为了轻量化，私钥保存在浏览器 `localStorage` 中，适合演示端到端加密流程，但不适合真实高安全场景。

生产版本建议升级：

- 使用 IndexedDB + WebCrypto non-extractable key 或原生 App Keychain/Keystore
- 使用 Signal Protocol，而不是简单 ECDH 会话密钥
- 增加身份密钥指纹校验和密钥变更提醒
- 给离线密文增加更严格的 TTL、队列限制和交付回执
- 做完整安全审计
