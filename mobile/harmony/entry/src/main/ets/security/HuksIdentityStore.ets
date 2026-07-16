/*
 * HUKS integration point.
 *
 * The exact HUKS parameter set depends on the target HarmonyOS SDK version.
 * Keep this wrapper as the only place that touches private identity keys.
 * Do not export private keys to preferences or files.
 */
export class HuksIdentityStore {
  async loadOrCreate(userId: string): Promise<Record<string, Object>> {
    /*
     * TODO in DevEco Studio:
     * - create EC P-256 key alias secure-burn-identity-${userId}
     * - return public JWK only
     * - keep private key non-exportable in HUKS
     */
    throw new Error(`HUKS key generation must be completed in DevEco Studio for ${userId}`);
  }

  async delete(userId: string): Promise<void> {
    /*
     * TODO:
     * - delete secure-burn-identity-${userId} from HUKS
     */
  }
}

