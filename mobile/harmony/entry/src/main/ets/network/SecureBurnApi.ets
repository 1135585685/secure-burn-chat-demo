const SERVER_BASE_URL = 'https://secure-burn-chat-demo.onrender.com';

export class SecureBurnApi {
  async register(userId: string, publicKey: Record<string, Object>): Promise<Record<string, Object>> {
    return this.post('/api/register', { userId, publicKey });
  }

  async getUser(userId: string): Promise<Record<string, Object>> {
    const response = await fetch(`${SERVER_BASE_URL}/api/users/${encodeURIComponent(userId)}`);
    return response.json();
  }

  async addFriend(userId: string, friendId: string, publicKey: Record<string, Object>): Promise<Record<string, Object>> {
    return this.post('/api/friends', { userId, friend: { userId: friendId, publicKey } });
  }

  private async post(path: string, body: Record<string, Object>): Promise<Record<string, Object>> {
    const response = await fetch(`${SERVER_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    return response.json();
  }
}

