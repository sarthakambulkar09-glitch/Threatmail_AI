import {
  signInWithPopup,
  GoogleAuthProvider,
  onAuthStateChanged,
  User,
  signOut,
  Auth,
} from 'firebase/auth';
import { auth, googleProvider } from '../firebase/config';
import firebaseConfig from '../../firebase-applet-config.json';

// Public Google Workspace and Identity scopes
export const AUTH_SCOPES = [
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'openid',
];

// Incremental scope required specifically for reading Gmail inbox
export const GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
];

// Combined scopes list for backward compatibility
export const SCOPES = [...AUTH_SCOPES, ...GMAIL_SCOPES];

// Base provider configured strictly with public, non-restricted identity scopes.
// Avoids "Access blocked: ThreatMail AI has not completed the Google verification process"
// error when any Google user signs in or signs up.
const provider: GoogleAuthProvider = googleProvider || new GoogleAuthProvider();
try {
  provider.addScope('email');
  provider.addScope('profile');
  provider.setCustomParameters({
    prompt: 'select_account',
  });
} catch (err) {
  console.warn('Firebase Auth provider configuration note:', err);
}

export { auth };

// Token memory caching (DO NOT store in localStorage or sessionStorage per security guidelines)
let cachedAccessToken: string | null = null;
let cachedGmailToken: string | null = null;
let cachedUser: User | null = null;
let isSigningIn = false;

export const getAccessToken = (): string | null => cachedAccessToken;
export const setAccessToken = (token: string | null) => {
  cachedAccessToken = token;
};
export const getGmailToken = (): string | null => cachedGmailToken;
export const setGmailToken = (token: string | null) => {
  cachedGmailToken = token;
};
export const hasGmailToken = (): boolean => !!cachedGmailToken;

// Helper to construct a synthetic User object when GIS token client is used
export const createProfileUser = (
  email: string,
  displayName?: string,
  photoURL?: string,
  uid?: string
): User => {
  const safeEmail = email || 'user@threatmail.ai';
  const synthetic: Partial<User> = {
    uid: uid || `g-${safeEmail.replace(/[^a-zA-Z0-9]/g, '_')}`,
    email: safeEmail,
    displayName: displayName || (safeEmail.includes('@') ? safeEmail.split('@')[0] : safeEmail),
    photoURL: photoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(safeEmail)}&background=2563eb&color=fff`,
    emailVerified: true,
    isAnonymous: false,
    metadata: {} as any,
    providerData: [],
    refreshToken: '',
    tenantId: null,
    delete: async () => {},
    getIdToken: async () => cachedAccessToken || '',
    getIdTokenResult: async () => ({} as any),
    reload: async () => {},
    toJSON: () => ({}),
    phoneNumber: null,
    providerId: 'google.com',
  };
  return synthetic as User;
};

// Initialize Auth listener
export const initAuth = (
  onAuthSuccess?: (user: User, token: string) => void,
  onAuthFailure?: () => void
) => {
  if (!auth) {
    if (cachedUser && cachedAccessToken) {
      if (onAuthSuccess) onAuthSuccess(cachedUser, cachedAccessToken);
    } else {
      if (onAuthFailure) onAuthFailure();
    }
    return () => {};
  }

  try {
    return onAuthStateChanged(auth, async (firebaseUser: User | null) => {
      if (firebaseUser) {
        cachedUser = firebaseUser;
        if (cachedAccessToken) {
          if (onAuthSuccess) onAuthSuccess(firebaseUser, cachedAccessToken);
        } else if (!isSigningIn) {
          // Token needs acquisition
          if (onAuthFailure) onAuthFailure();
        }
      } else if (cachedUser && cachedAccessToken) {
        if (onAuthSuccess) onAuthSuccess(cachedUser, cachedAccessToken);
      } else {
        cachedUser = null;
        cachedAccessToken = null;
        if (onAuthFailure) onAuthFailure();
      }
    });
  } catch (err) {
    console.warn('onAuthStateChanged error handled:', err);
    if (onAuthFailure) onAuthFailure();
    return () => {};
  }
};

// Fetch user information from Google APIs using access token
async function fetchGoogleUserInfo(token: string): Promise<{ email: string; name?: string; picture?: string }> {
  try {
    const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.email) {
        return {
          email: data.email,
          name: data.name || data.email.split('@')[0],
          picture: data.picture,
        };
      }
    }
  } catch (e) {
    console.warn('UserInfo fetch error, falling back to Gmail profile:', e);
  }

  try {
    const gmailProfileRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (gmailProfileRes.ok) {
      const gmailData = await gmailProfileRes.json();
      return {
        email: gmailData.emailAddress || 'user@gmail.com',
        name: gmailData.emailAddress?.split('@')[0],
      };
    }
  } catch (e) {
    console.warn('Gmail profile fetch error:', e);
  }

  return { email: 'user@gmail.com' };
}

// Check if there is a live valid Google OAuth access token
export const hasLiveOAuthToken = (): boolean => {
  return !!cachedAccessToken && !cachedAccessToken.startsWith('analyst-token-') && !cachedAccessToken.startsWith('local-');
};

// Perform Google Sign-In with official Firebase Auth & Google Identity Services
// Uses strictly basic identity scopes (email, profile) so ANY Google account can sign in
// without being blocked by unverified app restrictions.
export const googleSignIn = async (loginHint?: string): Promise<{ user: User; accessToken: string }> => {
  isSigningIn = true;
  const clientId = (firebaseConfig as any)?.oAuthClientId;

  // 1. Primary: Firebase Auth popup with non-restricted Google provider
  if (auth && provider) {
    try {
      const result = await signInWithPopup(auth, provider);
      const credential = GoogleAuthProvider.credentialFromResult(result);
      let token = credential?.accessToken;
      if (!token && result.user) {
        token = await result.user.getIdToken();
      }
      cachedUser = result.user;
      cachedAccessToken = token || `auth-${result.user.uid}`;
      isSigningIn = false;
      return { user: result.user, accessToken: cachedAccessToken };
    } catch (firebaseErr: any) {
      console.warn('Firebase popup sign-in attempt note:', firebaseErr?.code || firebaseErr?.message);
      if (firebaseErr?.code === 'auth/popup-closed-by-user') {
        isSigningIn = false;
        throw new Error('Google sign-in popup was closed before completing. Please try again.');
      }
      if (firebaseErr?.code === 'auth/popup-blocked') {
        isSigningIn = false;
        throw new Error('Sign-in popup was blocked by your browser. Please allow popups for this site and try again.');
      }
    }
  }

  // 2. Secondary: Try Google Identity Services token client with non-restricted AUTH_SCOPES
  if (typeof window !== 'undefined' && (window as any).google?.accounts?.oauth2 && clientId) {
    try {
      const tokenPromise = new Promise<{ user: User; accessToken: string }>((resolve, reject) => {
        const tokenClient = (window as any).google.accounts.oauth2.initTokenClient({
          client_id: clientId,
          scope: AUTH_SCOPES.join(' '),
          hint: loginHint || undefined,
          prompt: 'select_account',
          callback: async (response: any) => {
            if (response.error) {
              reject(new Error(response.error_description || response.error));
              return;
            }
            if (!response.access_token) {
              reject(new Error('No access token returned from Google authorization'));
              return;
            }

            const token = response.access_token;
            cachedAccessToken = token;

            try {
              const info = await fetchGoogleUserInfo(token);
              const userEmail = info.email || loginHint || 'user@gmail.com';
              const userObj = createProfileUser(userEmail, info.name, info.picture);
              cachedUser = userObj;
              resolve({ user: userObj, accessToken: token });
            } catch (profileErr) {
              console.warn('Profile read fallback:', profileErr);
              const fallbackEmail = loginHint || 'user@gmail.com';
              const genericUser = createProfileUser(fallbackEmail, 'Google User');
              cachedUser = genericUser;
              resolve({ user: genericUser, accessToken: token });
            }
          },
        });

        tokenClient.requestAccessToken({ prompt: 'select_account', hint: loginHint });
      });

      const result = await tokenPromise;
      isSigningIn = false;
      return result;
    } catch (gisError: any) {
      console.warn('Google Identity Services client attempt:', gisError?.message || gisError);
      if (gisError?.message?.includes('closed') || gisError?.message?.includes('user_cancel')) {
        isSigningIn = false;
        throw new Error('Google sign-in window was closed. Please try again.');
      }
    }
  }

  isSigningIn = false;
  throw new Error('Google Sign-In service is initializing. Please try again or select your email directly.');
};

// Request incremental Gmail API permission specifically for reading real inbox messages
export const requestGmailAccess = async (loginHint?: string): Promise<string> => {
  const clientId = (firebaseConfig as any)?.oAuthClientId;

  // 1. Try Google Identity Services token client with gmail.readonly
  if (typeof window !== 'undefined' && (window as any).google?.accounts?.oauth2 && clientId) {
    try {
      const tokenPromise = new Promise<string>((resolve, reject) => {
        const tokenClient = (window as any).google.accounts.oauth2.initTokenClient({
          client_id: clientId,
          scope: 'https://www.googleapis.com/auth/gmail.readonly',
          hint: loginHint || undefined,
          prompt: 'consent',
          callback: (response: any) => {
            if (response.error) {
              reject(new Error(response.error_description || response.error));
              return;
            }
            if (!response.access_token) {
              reject(new Error('No access token returned for Gmail API'));
              return;
            }
            cachedAccessToken = response.access_token;
            cachedGmailToken = response.access_token;
            resolve(response.access_token);
          },
        });
        tokenClient.requestAccessToken({ prompt: 'consent', hint: loginHint });
      });

      return await tokenPromise;
    } catch (gisErr: any) {
      console.warn('GIS Gmail scope attempt error:', gisErr?.message || gisErr);
      throw gisErr;
    }
  }

  // 2. Try Firebase Auth popup with Gmail scope provider
  if (auth) {
    try {
      const gmailProvider = new GoogleAuthProvider();
      gmailProvider.addScope('https://www.googleapis.com/auth/gmail.readonly');
      gmailProvider.setCustomParameters({
        prompt: 'consent',
        ...(loginHint ? { login_hint: loginHint } : {}),
      });
      const result = await signInWithPopup(auth, gmailProvider);
      const credential = GoogleAuthProvider.credentialFromResult(result);
      if (credential?.accessToken) {
        cachedAccessToken = credential.accessToken;
        cachedGmailToken = credential.accessToken;
        return credential.accessToken;
      }
    } catch (fbErr: any) {
      console.warn('Firebase Gmail scope attempt note:', fbErr);
      throw fbErr;
    }
  }

  throw new Error('Could not obtain Gmail access token.');
};

export const logout = async () => {
  if (auth) {
    try {
      await signOut(auth);
    } catch (err) {
      console.warn('SignOut error:', err);
    }
  }
  cachedAccessToken = null;
  cachedGmailToken = null;
  cachedUser = null;
};

// Switch / sign in directly as a specified analyst email (for testing isolation & user management)
export const loginAsUserEmail = (email: string, displayName?: string): User => {
  const cleanEmail = email.toLowerCase().trim();
  const name = displayName || cleanEmail.split('@')[0];
  const user = createProfileUser(cleanEmail, name, undefined, `user_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`);
  cachedUser = user;
  cachedAccessToken = 'analyst-token-' + cleanEmail.replace(/[^a-zA-Z0-9]/g, '_');
  return user;
};

