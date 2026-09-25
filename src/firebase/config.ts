import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import { initializeFirestore, getFirestore } from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

// Firebase initialization for Client Authentication & Firestore Database
export const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);

const databaseId = (firebaseConfig as any).firestoreDatabaseId || undefined;

// Use long-polling transport to reliably avoid connection drops in iframe sandbox and reverse proxies
export const db = (() => {
  try {
    return initializeFirestore(
      app,
      {
        experimentalForceLongPolling: true,
      },
      databaseId
    );
  } catch {
    return getFirestore(app, databaseId);
  }
})();

export const googleProvider = new GoogleAuthProvider();

