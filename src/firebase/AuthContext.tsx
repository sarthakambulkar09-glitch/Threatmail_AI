import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  User,
  signInWithPopup,
  signOut as fbSignOut,
  onAuthStateChanged,
} from 'firebase/auth';
import { auth, googleProvider } from './config';
import {
  getUserProfileFromFirestore,
  saveUserProfileToFirestore,
  UserProfileData,
} from './firestoreService';

export type UserProfile = UserProfileData;

interface AuthContextType {
  user: User | null;
  userProfile: UserProfile | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signOut: () => Promise<void>;
  error: string | null;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  userProfile: null,
  loading: true,
  signInWithGoogle: async () => {},
  signOut: async () => {},
  error: null,
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        try {
          const profile = await getUserProfileFromFirestore(currentUser.uid);
          if (profile) {
            setUserProfile(profile);
          } else {
            const newProfile: UserProfile = {
              uid: currentUser.uid,
              email: currentUser.email || 'analyst@threatmail.soc',
              displayName: currentUser.displayName || 'SOC Analyst',
              photoURL: currentUser.photoURL || '',
              role: 'Security Analyst',
              createdAt: new Date().toISOString(),
            };
            await saveUserProfileToFirestore(newProfile);
            setUserProfile(newProfile);
          }
        } catch (err: unknown) {
          console.warn('Error reading/syncing user document in Firestore:', err);
          // Non-blocking fallback for local session
          setUserProfile({
            uid: currentUser.uid,
            email: currentUser.email || 'analyst@threatmail.soc',
            displayName: currentUser.displayName || 'SOC Analyst',
            photoURL: currentUser.photoURL || '',
            role: 'Security Analyst',
            createdAt: new Date().toISOString(),
          });
        }
      } else {
        setUserProfile(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    setError(null);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const currentUser = result.user;
      const newProfile: UserProfile = {
        uid: currentUser.uid,
        email: currentUser.email || '',
        displayName: currentUser.displayName || 'SOC Analyst',
        photoURL: currentUser.photoURL || '',
        role: 'Security Analyst',
        createdAt: new Date().toISOString(),
      };
      try {
        await saveUserProfileToFirestore(newProfile);
        setUserProfile(newProfile);
      } catch (e) {
        console.warn('Firestore user profile write warning:', e);
        setUserProfile(newProfile);
      }
    } catch (err: any) {
      console.error('Google Sign-In Error:', err);
      setError(err?.message || 'Failed to sign in with Google');
    }
  };

  const signOut = async () => {
    try {
      await fbSignOut(auth);
      setUser(null);
      setUserProfile(null);
    } catch (err: any) {
      console.error('Sign Out Error:', err);
    }
  };

  return (
    <AuthContext.Provider value={{ user, userProfile, loading, signInWithGoogle, signOut, error }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
