import {
  collection,
  doc,
  setDoc,
  getDoc,
  getDocs,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  limit,
} from 'firebase/firestore';
import { db, auth } from './config';
import { handleFirestoreError, OperationType } from './errorHandler';
import { EmailThreatReport } from '../types';

export interface UserProfileData {
  uid: string;
  email: string;
  displayName: string;
  photoURL: string;
  role: string;
  createdAt: string;
}

export interface PersistedChatMessage {
  id: string;
  userId: string;
  role: 'user' | 'model' | 'system';
  model: string;
  text: string;
  createdAt: string;
  groundingLinks?: { title: string; uri: string; sourceType?: string; snippet?: string }[];
}

const STORAGE_PREFIX = 'threatmail_firestore_cache_';
const getStorageKey = (userId: string, col: string) => `${STORAGE_PREFIX}${userId}_${col}`;

function getLocalCache<T>(key: string, defaultValue: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return defaultValue;
    return JSON.parse(raw);
  } catch {
    return defaultValue;
  }
}

function setLocalCache<T>(key: string, value: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore storage quota limits
  }
}

/**
 * Saves or updates user profile in Cloud Firestore (/users/{userId})
 */
export async function saveUserProfileToFirestore(profile: UserProfileData): Promise<void> {
  if (!profile.uid) return;
  const cacheKey = getStorageKey(profile.uid, 'profile');
  setLocalCache(cacheKey, profile);

  // If user is not authenticated with Firebase, remain in local storage mode
  if (!auth.currentUser || auth.currentUser.uid !== profile.uid) {
    return;
  }

  const userPath = `users/${profile.uid}`;
  try {
    const userRef = doc(db, 'users', profile.uid);
    await setDoc(
      userRef,
      {
        uid: profile.uid,
        email: profile.email || 'analyst@threatmail.ai',
        displayName: profile.displayName || 'SOC Analyst',
        photoURL: profile.photoURL || '',
        role: profile.role || 'Security Analyst',
        createdAt: profile.createdAt || new Date().toISOString(),
      },
      { merge: true }
    );
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.WRITE, userPath);
    }
    console.warn('[Firestore] Failed to save user profile (using local cache):', err?.message);
  }
}

/**
 * Retrieves user profile from Cloud Firestore (/users/{userId})
 */
export async function getUserProfileFromFirestore(userId: string): Promise<UserProfileData | null> {
  if (!userId) return null;
  const cacheKey = getStorageKey(userId, 'profile');
  const cached = getLocalCache<UserProfileData | null>(cacheKey, null);

  // If user is not authenticated with Firebase, return local cache
  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return cached;
  }

  const userPath = `users/${userId}`;
  try {
    const userRef = doc(db, 'users', userId);
    const snap = await getDoc(userRef);
    if (snap.exists()) {
      const data = snap.data() as UserProfileData;
      setLocalCache(cacheKey, data);
      return data;
    }
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.GET, userPath);
    }
    console.warn('[Firestore] Profile fetch error, using cache:', err?.message);
  }

  return cached;
}

/**
 * Persists an email threat report to Firestore under /users/{userId}/threatReports/{reportId}
 */
export async function saveThreatReportToFirestore(
  userId: string,
  report: EmailThreatReport
): Promise<void> {
  if (!userId || !report.id) return;
  const cacheKey = getStorageKey(userId, 'threatReports');

  // Sanitize and ensure strict compliance with firestore.rules
  const sanitizedId = String(report.id).replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 128);
  const docData = {
    id: sanitizedId,
    userId,
    subject: (report.subject || '(No Subject)').slice(0, 500),
    senderEmail: (report.sender?.email || 'unknown@domain.com').slice(0, 256),
    riskScore: Math.min(100, Math.max(0, Number(report.riskScore) || 0)),
    classification: (report.classification || 'Safe').slice(0, 64),
    status: (report.status || 'scanned').slice(0, 32),
    scannedAt: (report.scannedAt || new Date().toISOString()).slice(0, 64),
    payload: JSON.stringify(report),
  };

  // Optimistic local cache update
  const cached = getLocalCache<any[]>(cacheKey, []);
  const existingIdx = cached.findIndex((r) => r.id === sanitizedId);
  if (existingIdx >= 0) {
    cached[existingIdx] = { ...cached[existingIdx], ...report, id: sanitizedId };
  } else {
    cached.unshift({ ...report, id: sanitizedId });
  }
  setLocalCache(cacheKey, cached);

  // If user is not authenticated with Firebase, stay in local cache mode
  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return;
  }

  const reportPath = `users/${userId}/threatReports/${sanitizedId}`;
  try {
    const reportRef = doc(db, 'users', userId, 'threatReports', sanitizedId);
    await setDoc(reportRef, docData, { merge: true });
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.WRITE, reportPath);
    }
    console.warn('[Firestore] Failed to persist threat report (using local cache):', err?.message);
  }
}

/**
 * Fetches threat reports for user from Firestore (/users/{userId}/threatReports)
 */
export async function getThreatReportsFromFirestore(userId: string): Promise<EmailThreatReport[]> {
  if (!userId) return [];
  const cacheKey = getStorageKey(userId, 'threatReports');
  const cached = getLocalCache<EmailThreatReport[]>(cacheKey, []);

  // If user is not authenticated with Firebase, return local cache
  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return cached;
  }

  const reportsPath = `users/${userId}/threatReports`;
  try {
    const colRef = collection(db, 'users', userId, 'threatReports');
    const q = query(colRef, orderBy('scannedAt', 'desc'), limit(100));
    const snap = await getDocs(q);

    if (!snap.empty) {
      const reports: EmailThreatReport[] = [];
      snap.forEach((d) => {
        const data = d.data();
        if (data.payload) {
          try {
            reports.push({ ...JSON.parse(data.payload), ...data });
            return;
          } catch {
            // fallback below
          }
        }
        reports.push(data as any);
      });
      setLocalCache(cacheKey, reports);
      return reports;
    }
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.LIST, reportsPath);
    }
    console.warn('[Firestore] Failed to query threat reports (using local cache):', err?.message);
  }

  return cached;
}

/**
 * Real-time subscription to user threat reports in Cloud Firestore
 */
export function subscribeThreatReportsFromFirestore(
  userId: string,
  onData: (reports: EmailThreatReport[]) => void
): () => void {
  if (!userId) {
    onData([]);
    return () => {};
  }

  const cacheKey = getStorageKey(userId, 'threatReports');
  const initial = getLocalCache<EmailThreatReport[]>(cacheKey, []);
  if (initial.length > 0) {
    onData(initial);
  }

  // If user is not authenticated with Firebase, use local cache only
  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return () => {};
  }

  const reportsPath = `users/${userId}/threatReports`;
  try {
    const colRef = collection(db, 'users', userId, 'threatReports');
    const q = query(colRef, orderBy('scannedAt', 'desc'), limit(100));

    const unsubscribe = onSnapshot(
      q,
      (snapshot) => {
        const reports: EmailThreatReport[] = [];
        snapshot.forEach((d) => {
          const data = d.data();
          if (data.payload) {
            try {
              reports.push({ ...JSON.parse(data.payload), ...data });
              return;
            } catch {
              // fallback
            }
          }
          reports.push(data as any);
        });

        // Merge with locally held recent reports that might still be syncing
        const currentCached = getLocalCache<EmailThreatReport[]>(cacheKey, []);
        const map = new Map<string, EmailThreatReport>();
        reports.forEach((r) => map.set(r.id, r));
        currentCached.forEach((r) => {
          if (!map.has(r.id)) map.set(r.id, r);
        });

        const merged = Array.from(map.values()).sort(
          (a, b) => new Date(b.scannedAt).getTime() - new Date(a.scannedAt).getTime()
        );
        setLocalCache(cacheKey, merged);
        onData(merged);
      },
      (error) => {
        if (error?.code === 'permission-denied') {
          handleFirestoreError(error, OperationType.LIST, reportsPath);
        }
        console.warn('[Firestore] Real-time threatReports subscription notice:', error.message);
        onData(getLocalCache<EmailThreatReport[]>(cacheKey, []));
      }
    );

    return unsubscribe;
  } catch (err: any) {
    console.warn('[Firestore] Error setting up real-time listener:', err?.message);
    return () => {};
  }
}

/**
 * Deletes a threat report from Firestore (/users/{userId}/threatReports/{reportId})
 */
export async function deleteThreatReportFromFirestore(
  userId: string,
  reportId: string
): Promise<void> {
  if (!userId || !reportId) return;
  const sanitizedId = String(reportId).replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 128);

  const cacheKey = getStorageKey(userId, 'threatReports');
  const cached = getLocalCache<EmailThreatReport[]>(cacheKey, []);
  setLocalCache(
    cacheKey,
    cached.filter((r) => r.id !== sanitizedId && r.id !== reportId)
  );

  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return;
  }

  const reportPath = `users/${userId}/threatReports/${sanitizedId}`;
  try {
    const reportRef = doc(db, 'users', userId, 'threatReports', sanitizedId);
    await deleteDoc(reportRef);
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.DELETE, reportPath);
    }
    console.warn('[Firestore] Error deleting report from Firestore (local cache updated):', err?.message);
  }
}

/**
 * Persists a SOC chat message to Firestore (/users/{userId}/chatMessages/{messageId})
 */
export async function saveChatMessageToFirestore(
  userId: string,
  message: PersistedChatMessage
): Promise<void> {
  if (!userId || !message.id) return;
  const sanitizedId = String(message.id).replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 128);
  const cacheKey = getStorageKey(userId, 'chatMessages');

  const docData = {
    id: sanitizedId,
    userId,
    role: message.role,
    model: (message.model || 'gemini-3.5-flash').slice(0, 128),
    text: (message.text || '').slice(0, 30000),
    createdAt: (message.createdAt || new Date().toISOString()).slice(0, 64),
    groundingLinks: message.groundingLinks || [],
  };

  const cached = getLocalCache<PersistedChatMessage[]>(cacheKey, []);
  if (!cached.some((m) => m.id === sanitizedId)) {
    cached.push({ ...message, id: sanitizedId });
    setLocalCache(cacheKey, cached);
  }

  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return;
  }

  const chatPath = `users/${userId}/chatMessages/${sanitizedId}`;
  try {
    const chatRef = doc(db, 'users', userId, 'chatMessages', sanitizedId);
    await setDoc(chatRef, docData, { merge: true });
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.WRITE, chatPath);
    }
    console.warn('[Firestore] Error saving chat message (using local cache):', err?.message);
  }
}

/**
 * Real-time subscription to SOC chat messages in Cloud Firestore
 */
export function subscribeChatMessagesFromFirestore(
  userId: string,
  onData: (messages: PersistedChatMessage[]) => void
): () => void {
  if (!userId) {
    onData([]);
    return () => {};
  }

  const cacheKey = getStorageKey(userId, 'chatMessages');
  const initial = getLocalCache<PersistedChatMessage[]>(cacheKey, []);
  if (initial.length > 0) {
    onData(initial);
  }

  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return () => {};
  }

  const chatColPath = `users/${userId}/chatMessages`;
  try {
    const colRef = collection(db, 'users', userId, 'chatMessages');
    const q = query(colRef, orderBy('createdAt', 'asc'), limit(100));

    const unsubscribe = onSnapshot(
      q,
      (snapshot) => {
        const msgs: PersistedChatMessage[] = [];
        snapshot.forEach((d) => {
          const data = d.data() as PersistedChatMessage;
          msgs.push(data);
        });

        // Merge with cached
        const currentCached = getLocalCache<PersistedChatMessage[]>(cacheKey, []);
        const map = new Map<string, PersistedChatMessage>();
        msgs.forEach((m) => map.set(m.id, m));
        currentCached.forEach((m) => {
          if (!map.has(m.id)) map.set(m.id, m);
        });

        const merged = Array.from(map.values()).sort(
          (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
        );
        setLocalCache(cacheKey, merged);
        onData(merged);
      },
      (error) => {
        if (error?.code === 'permission-denied') {
          handleFirestoreError(error, OperationType.LIST, chatColPath);
        }
        console.warn('[Firestore] Real-time chatMessages subscription notice:', error.message);
        onData(getLocalCache<PersistedChatMessage[]>(cacheKey, []));
      }
    );

    return unsubscribe;
  } catch (err: any) {
    console.warn('[Firestore] Error subscribing to chat messages:', err?.message);
    return () => {};
  }
}

/**
 * Clears user chat messages from Firestore
 */
export async function clearChatMessagesFromFirestore(userId: string): Promise<void> {
  if (!userId) return;
  const cacheKey = getStorageKey(userId, 'chatMessages');
  setLocalCache(cacheKey, []);

  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return;
  }

  const chatColPath = `users/${userId}/chatMessages`;
  try {
    const colRef = collection(db, 'users', userId, 'chatMessages');
    const snap = await getDocs(colRef);
    const deletes = snap.docs.map((d) => deleteDoc(d.ref));
    await Promise.all(deletes);
  } catch (err: any) {
    if (err?.code === 'permission-denied') {
      handleFirestoreError(err, OperationType.DELETE, chatColPath);
    }
    console.warn('[Firestore] Error clearing chat messages:', err?.message);
  }
}
