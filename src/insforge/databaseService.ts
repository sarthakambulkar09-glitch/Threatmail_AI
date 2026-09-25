import { EmailThreatReport } from '../types';
import {
  UserProfileData,
  PersistedChatMessage,
  saveUserProfileToFirestore,
  getUserProfileFromFirestore,
  saveThreatReportToFirestore,
  getThreatReportsFromFirestore,
  subscribeThreatReportsFromFirestore,
  deleteThreatReportFromFirestore,
  saveChatMessageToFirestore,
  subscribeChatMessagesFromFirestore,
  clearChatMessagesFromFirestore,
} from '../firebase/firestoreService';

export type { UserProfileData, PersistedChatMessage };

/**
 * Persists a threat report to Firestore database
 */
export async function saveUserThreatReport(
  userId: string,
  report: EmailThreatReport
): Promise<void> {
  return saveThreatReportToFirestore(userId, report);
}

/**
 * Fetches user threat reports from Firestore
 */
export async function getUserThreatReports(userId: string): Promise<EmailThreatReport[]> {
  return getThreatReportsFromFirestore(userId);
}

/**
 * Subscribes to user's threat reports in real-time with Firestore onSnapshot
 */
export function subscribeUserThreatReports(
  userId: string,
  onData: (reports: EmailThreatReport[]) => void
): () => void {
  return subscribeThreatReportsFromFirestore(userId, onData);
}

/**
 * Deletes a threat report from Firestore
 */
export async function deleteUserThreatReport(
  userId: string,
  reportId: string
): Promise<void> {
  return deleteThreatReportFromFirestore(userId, reportId);
}

/**
 * Persists chat message to Firestore database
 */
export async function saveUserChatMessage(
  userId: string,
  message: PersistedChatMessage
): Promise<void> {
  return saveChatMessageToFirestore(userId, message);
}

/**
 * Subscribes to chat message history in real-time from Firestore
 */
export function subscribeUserChatMessages(
  userId: string,
  onData: (messages: PersistedChatMessage[]) => void
): () => void {
  return subscribeChatMessagesFromFirestore(userId, onData);
}

/**
 * Clears chat history for a user from Firestore
 */
export async function clearUserChatMessages(userId: string): Promise<void> {
  return clearChatMessagesFromFirestore(userId);
}

/**
 * Saves analyst profile to Firestore database (/users/{userId})
 */
export async function saveUserProfileToInsForge(profile: UserProfileData): Promise<void> {
  return saveUserProfileToFirestore(profile);
}

/**
 * Retrieves analyst profile from Firestore database (/users/{userId})
 */
export async function getUserProfileFromInsForge(
  userId: string
): Promise<UserProfileData | null> {
  return getUserProfileFromFirestore(userId);
}
