import { SecureBurnApi } from '../network/SecureBurnApi';
import { SecureBurnSocket } from '../network/SecureBurnSocket';
import { HuksIdentityStore } from '../security/HuksIdentityStore';

@Entry
@Component
struct Index {
  @State userId: string = '';
  @State friendId: string = '';
  @State message: string = '';
  @State status: string = '未连接';
  @State currentMessage: string = '';

  private api: SecureBurnApi = new SecureBurnApi();
  private socket: SecureBurnSocket = new SecureBurnSocket();
  private identity: HuksIdentityStore = new HuksIdentityStore();
  private publicKey?: Record<string, Object>;
  private friendPublicKey?: Record<string, Object>;

  build() {
    Column({ space: 12 }) {
      Text('Secure Burn HarmonyOS').fontSize(24).fontWeight(FontWeight.Bold)

      TextInput({ placeholder: '你的 ID', text: this.userId })
        .onChange((value: string) => this.userId = value)

      Button('登入').onClick(async () => {
        try {
          this.publicKey = await this.identity.loadOrCreate(this.userId);
          await this.api.register(this.userId, this.publicKey);
          this.socket.connect(this.userId, this.publicKey, (event) => {
            if (event['type'] === 'message') {
              this.currentMessage = `${event['from']}: 收到加密消息`;
            }
            this.status = String(event['type'] || 'event');
          });
          this.status = '已登入';
        } catch (error) {
          this.status = `登入失败：${String(error)}`;
        }
      })

      TextInput({ placeholder: '好友 ID', text: this.friendId })
        .onChange((value: string) => this.friendId = value)

      Button('添加好友').onClick(async () => {
        const friend = await this.api.getUser(this.friendId);
        this.friendPublicKey = friend['publicKey'] as Record<string, Object>;
        await this.api.addFriend(this.userId, this.friendId, this.friendPublicKey);
        this.status = `已添加好友 ${this.friendId}`;
      })

      TextInput({ placeholder: '消息', text: this.message })
        .onChange((value: string) => this.message = value)

      Button('发送加密消息').onClick(() => {
        /*
         * TODO after HUKS ECDH wrapper is complete:
         * - derive shared secret with friendPublicKey
         * - AES-GCM encrypt payload
         * - send WebSocket message
         */
        this.status = 'HarmonyOS 加密发送逻辑待 HUKS ECDH 完成';
      })

      Text(this.status).fontSize(12)
      Text(this.currentMessage).fontSize(16)
    }
    .padding(16)
    .width('100%')
    .height('100%')
  }
}

