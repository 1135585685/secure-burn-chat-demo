export interface Friend {
  userId: string;
  publicKey: Record<string, Object>;
  fingerprint: string;
  confirmed: boolean;
  online: boolean;
}

