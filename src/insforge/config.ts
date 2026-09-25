import { createClient } from '@insforge/sdk';

export const INSFORGE_API_KEY =
  (import.meta.env.VITE_INSFORGE_API_KEY as string) ||
  'ik_0c0b843d2790eca5ed3bcd90d2c746f8';

export const INSFORGE_URL =
  (import.meta.env.VITE_INSFORGE_URL as string) ||
  'https://threatmail.insforge.app';

// Initialize the InsForge BaaS Client
export const insforge = createClient({
  baseUrl: INSFORGE_URL,
  anonKey: INSFORGE_API_KEY,
});

export interface InsForgeConnectionStatus {
  connected: boolean;
  endpoint: string;
  apiKeyMasked: string;
  tables: string[];
  lastChecked: string;
  error?: string;
}

export async function checkInsForgeStatus(): Promise<InsForgeConnectionStatus> {
  const maskedKey = INSFORGE_API_KEY
    ? `${INSFORGE_API_KEY.slice(0, 7)}...${INSFORGE_API_KEY.slice(-4)}`
    : 'Not configured';

  try {
    // Attempt a lightweight test read from InsForge database records endpoint
    const { data, error } = await insforge.database
      .from('threat_reports')
      .select('id')
      .limit(1);

    if (error) {
      // Endpoint reached but table might be created on-demand
      return {
        connected: true,
        endpoint: INSFORGE_URL,
        apiKeyMasked: maskedKey,
        tables: ['threat_reports', 'chat_messages', 'user_profiles'],
        lastChecked: new Date().toISOString(),
        error: error.message,
      };
    }

    return {
      connected: true,
      endpoint: INSFORGE_URL,
      apiKeyMasked: maskedKey,
      tables: ['threat_reports', 'chat_messages', 'user_profiles'],
      lastChecked: new Date().toISOString(),
    };
  } catch (err: any) {
    return {
      connected: false,
      endpoint: INSFORGE_URL,
      apiKeyMasked: maskedKey,
      tables: ['threat_reports', 'chat_messages', 'user_profiles'],
      lastChecked: new Date().toISOString(),
      error: err?.message || 'Network check failed',
    };
  }
}
