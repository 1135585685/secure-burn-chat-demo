const SERVER_WS_URL = 'wss://secure-burn-chat-demo.onrender.com';

export class SecureBurnSocket {
  private socket?: WebSocket;

  connect(userId: string, publicKey: Record<string, Object>, onMessage: (event: Record<string, Object>) => void): void {
    this.socket = new WebSocket(SERVER_WS_URL);
    this.socket.onopen = () => {
      this.socket?.send(JSON.stringify({ type: 'hello', userId, publicKey }));
    };
    this.socket.onmessage = (message) => {
      onMessage(JSON.parse(message.data as string));
    };
  }

  send(packet: Record<string, Object>): void {
    this.socket?.send(JSON.stringify(packet));
  }

  close(): void {
    this.socket?.close();
  }
}

