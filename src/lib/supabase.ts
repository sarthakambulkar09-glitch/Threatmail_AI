import { createClient, SupabaseClient } from '@supabase/supabase-js';

let supabaseClient: SupabaseClient | null = null;

export function getSupabaseClient(): SupabaseClient | null {
  if (supabaseClient) {
    return supabaseClient;
  }

  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

  if (supabaseUrl && supabaseAnonKey && supabaseUrl.trim() && supabaseAnonKey.trim()) {
    try {
      supabaseClient = createClient(supabaseUrl.trim(), supabaseAnonKey.trim());
      return supabaseClient;
    } catch (err) {
      console.warn('Failed to initialize Supabase client:', err);
      return null;
    }
  }

  return null;
}

export interface SupabaseThreatResult {
  threat_type?: string;
  [key: string]: any;
}

/**
 * Fetches threat_type rows live from Supabase 'results' table
 */
export async function fetchLiveThreatTypes(): Promise<string[] | null> {
  const client = getSupabaseClient();
  if (!client) {
    return null;
  }

  try {
    const { data, error } = await client
      .from('results')
      .select('threat_type');

    if (error) {
      console.warn("Supabase 'results' query error:", error.message);
      return null;
    }

    if (data && Array.isArray(data) && data.length > 0) {
      return data
        .map((row: SupabaseThreatResult) => row.threat_type)
        .filter((t): t is string => typeof t === 'string' && t.trim().length > 0);
    }

    return [];
  } catch (err) {
    console.warn('Failed to fetch from Supabase:', err);
    return null;
  }
}
