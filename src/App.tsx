import React, { useEffect, useState, useMemo } from 'react';
import { User } from 'firebase/auth';
import {
  initAuth,
  googleSignIn,
  requestGmailAccess,
  logout,
  getAccessToken,
  setAccessToken,
  getGmailToken,
  setGmailToken,
  hasGmailToken,
  createProfileUser,
  loginAsUserEmail,
  hasLiveOAuthToken,
} from './lib/auth';
import {
  fetchInsforgeScans,
  fetchInsforgeStats,
  fetchInsforgeNotifications,
  fetchInsforgeStatus,
  analyzeAndSaveEmail,
  scanSampleEmails,
  updateScanStatusInInsforge,
  deleteScanFromInsforge,
  markNotificationAsRead as apiMarkNotificationAsRead,
  markAllNotificationsAsRead as apiMarkAllNotificationsAsRead,
  InsforgeStatus,
} from './lib/insforgeClient';
import { fetchInboxMessages, fetchMessageDetail } from './lib/gmail';
import { generateForensicPdf } from './lib/pdfReport';
import { EmailThreatReport, InsforgeNotification, InsforgeStats } from './types';

// Redesigned Enterprise Components
import { Header } from './components/Header';
import { PrivateScanBanner } from './components/PrivateScanBanner';
import { LoginModal } from './components/LoginModal';
import { Sidebar, SidebarTab } from './components/Sidebar';
import { StatsBar } from './components/StatsBar';
import { SecurityCharts } from './components/SecurityCharts';
import { EmailListTable } from './components/EmailListTable';
import { EmailAnalysisPanel } from './components/EmailAnalysisPanel';
import { ThreatMapSection } from './components/ThreatMapSection';
import { ThreatDetailModal } from './components/ThreatDetailModal';
import { NotificationCenter } from './components/NotificationCenter';
import { UserProfileModal } from './components/UserProfileModal';
import { GeminiChatbot } from './components/GeminiChatbot';
import { LiveVoiceModal } from './components/LiveVoiceModal';
import { MapsGroundingView } from './components/MapsGroundingView';
import { ScanRealEmailModal } from './components/ScanRealEmailModal';
import { RealTimeLocationMonitor } from './components/RealTimeLocationMonitor';
import {
  saveUserThreatReport,
  subscribeUserThreatReports,
  deleteUserThreatReport,
} from './insforge/databaseService';

import {
  RefreshCw,
  AlertTriangle,
  FileDown,
  Shield,
  ChevronRight,
  Radio,
} from 'lucide-react';

export default function App() {
  // Authentication & Backend Status: Start unauthenticated (Do not show login directly)
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [insforgeStatus, setInsforgeStatus] = useState<InsforgeStatus | null>(null);

  // Core SOC Data State (strictly user-isolated)
  const [scans, setScans] = useState<EmailThreatReport[]>([]);
  const [stats, setStats] = useState<InsforgeStats>({
    totalScanned: 0,
    threatsBlocked: 0,
    safeEmails: 0,
    phishingCount: 0,
    malwareCount: 0,
    becCount: 0,
    averageRiskScore: 0,
    highRiskCount: 0,
    suspiciousCount: 0,
  });
  const [notifications, setNotifications] = useState<InsforgeNotification[]>([]);

  // Navigation & UI View State
  const [activeTab, setActiveTab] = useState<SidebarTab>('dashboard');
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState<boolean>(false);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<'all' | 'critical' | 'suspicious' | 'safe'>('all');

  // Operation States
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number; title: string } | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Modals & Panels
  const [isDetailModalOpen, setIsDetailModalOpen] = useState<boolean>(false);
  const [isNotificationOpen, setIsNotificationOpen] = useState<boolean>(false);
  const [isProfileOpen, setIsProfileOpen] = useState<boolean>(false);
  const [isVoiceModalOpen, setIsVoiceModalOpen] = useState<boolean>(false);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState<boolean>(false);
  const [isRealEmailModalOpen, setIsRealEmailModalOpen] = useState<boolean>(false);

  // Keep localStorage in sync with active user
  useEffect(() => {
    if (user?.email) {
      localStorage.setItem(
        'threatmail_active_user',
        JSON.stringify({
          email: user.email,
          displayName: user.displayName,
        })
      );
      sessionStorage.removeItem('threatmail_user_logged_out');
    } else {
      localStorage.removeItem('threatmail_active_user');
    }
  }, [user]);

  // Real-time computed statistics derived dynamically from user's verified scans
  const liveStats: InsforgeStats = useMemo(() => {
    if (!scans || scans.length === 0) {
      return {
        totalScanned: 0,
        threatsBlocked: 0,
        safeEmails: 0,
        phishingCount: 0,
        malwareCount: 0,
        becCount: 0,
        averageRiskScore: 0,
        highRiskCount: 0,
        suspiciousCount: 0,
        lastScannedAt: null,
      };
    }
    const totalScanned = scans.length;
    const safeEmails = scans.filter((s) => s.classification === 'Safe').length;
    const phishingCount = scans.filter((s) => s.classification === 'Phishing').length;
    const malwareCount = scans.filter((s) => s.classification === 'Malware Risk').length;
    const becCount = scans.filter((s) => s.classification === 'Business Email Compromise').length;
    const suspiciousCount = scans.filter((s) => s.classification === 'Suspicious').length;
    const highRiskCount = scans.filter((s) => (s.riskScore || 0) >= 70).length;
    const threatsBlocked = scans.filter((s) => s.status === 'quarantined' || (s.riskScore || 0) >= 70).length;
    const totalScore = scans.reduce((acc, curr) => acc + (curr.riskScore || 0), 0);
    const averageRiskScore = Math.round(totalScore / totalScanned);

    return {
      totalScanned,
      threatsBlocked,
      safeEmails,
      phishingCount,
      malwareCount,
      becCount,
      averageRiskScore,
      highRiskCount,
      suspiciousCount,
      lastScannedAt: scans[0]?.scannedAt || new Date().toISOString(),
    };
  }, [scans]);

  // 1. Initial Authentication Listener
  useEffect(() => {
    let unsubscribe: (() => void) | undefined;
    try {
      unsubscribe = initAuth(
        (currentUser, token) => {
          if (sessionStorage.getItem('threatmail_user_logged_out') !== 'true') {
            setUser(currentUser);
            if (token) setAccessToken(token);
          }
        },
        () => {
          // In case Firebase listener fires with null and user is logged out
          if (sessionStorage.getItem('threatmail_user_logged_out') === 'true') {
            setUser(null);
            setAccessToken(null);
          }
        }
      );
    } catch (e) {
      console.warn('Auth listener initialization note:', e);
    }

    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, []);

  // Reload data strictly isolated to current user's email
  const reloadUserData = async (emailOverride?: string) => {
    const activeEmail = (emailOverride || user?.email || '').toLowerCase().trim();
    if (!activeEmail) {
      setScans([]);
      setNotifications([]);
      setSelectedScanId(null);
      return;
    }

    try {
      const [scansRes, statsRes, notifsRes, statusRes] = await Promise.allSettled([
        fetchInsforgeScans(activeEmail),
        fetchInsforgeStats(activeEmail),
        fetchInsforgeNotifications(activeEmail),
        fetchInsforgeStatus(activeEmail),
      ]);

      if (scansRes.status === 'fulfilled' && Array.isArray(scansRes.value)) {
        setScans(scansRes.value);
        if (scansRes.value.length > 0) {
          if (!selectedScanId || !scansRes.value.some((s) => s.id === selectedScanId)) {
            setSelectedScanId(scansRes.value[0].id);
          }
        } else {
          setSelectedScanId(null);
        }
      }

      if (statsRes.status === 'fulfilled' && statsRes.value) {
        setStats(statsRes.value);
      }

      if (notifsRes.status === 'fulfilled' && Array.isArray(notifsRes.value)) {
        setNotifications(notifsRes.value);
      }

      if (statusRes.status === 'fulfilled' && statusRes.value) {
        setInsforgeStatus(statusRes.value);
      }
    } catch (err) {
      console.warn('SOC telemetry sync note:', err);
    }
  };

  // Whenever user email changes, instantly isolate scans
  useEffect(() => {
    if (!user?.email) {
      setScans([]);
      setNotifications([]);
      setSelectedScanId(null);
      return;
    }
    // Clear scans before fetching to guarantee zero cross-user display
    setScans([]);
    setSelectedScanId(null);
    reloadUserData(user.email);
  }, [user?.email]);

  // 2. Real-time Cloud Firestore Data Persistence for Authenticated User
  useEffect(() => {
    if (!user?.uid || !user?.email) return;
    const activeEmail = user.email.toLowerCase().trim();
    const unsubscribe = subscribeUserThreatReports(user.uid, (firestoreReports) => {
      if (firestoreReports && firestoreReports.length > 0) {
        // Filter strictly by current user email
        const isolated = firestoreReports.filter(
          (r) => (r.userEmail || r.recipient || '').toLowerCase().trim() === activeEmail
        );
        if (isolated.length > 0) {
          setScans((prev) => {
            const map = new Map<string, EmailThreatReport>();
            prev.forEach((r) => {
              if ((r.userEmail || r.recipient || '').toLowerCase().trim() === activeEmail) {
                map.set(r.id, r);
              }
            });
            isolated.forEach((r) => map.set(r.id, r));
            return Array.from(map.values()).sort(
              (a, b) => new Date(b.scannedAt).getTime() - new Date(a.scannedAt).getTime()
            );
          });
        }
      }
    });

    return () => unsubscribe();
  }, [user?.uid, user?.email]);

  // Real-time periodic telemetry poll strictly for active user
  useEffect(() => {
    if (!user?.email) return;
    const timer = setInterval(() => {
      if (!isScanning && !isSyncing && user?.email) {
        reloadUserData(user.email);
      }
    }, 8000);
    return () => clearInterval(timer);
  }, [isScanning, isSyncing, user?.email]);

  // Gmail Real-time Inbox Scanning with OAuth token (Actual user emails)
  const scanInboxWithToken = async (
    currentToken: string,
    targetUser?: User | null,
    maxCount: number = 5,
    query: string = 'in:inbox',
    isUserInitiated: boolean = false
  ) => {
    if (!currentToken || currentToken === 'analyst-token-active') {
      setErrorMessage('Please connect your Google account to scan live Gmail emails.');
      return;
    }

    setIsSyncing(true);
    setIsScanning(true);
    setErrorMessage(null);

    const startTime = performance.now();

    try {
      setScanProgress({
        current: 0,
        total: 1,
        title: `Connecting to Gmail API for ${targetUser?.email || user?.email || 'account'}...`,
      });

      let emailRefs: { id: string; threadId: string }[] = [];
      try {
        emailRefs = await fetchInboxMessages(currentToken, maxCount, query);
      } catch (fetchErr: any) {
        if (
          fetchErr?.message &&
          (fetchErr.message.includes('ACCESS_TOKEN_SCOPE_INSUFFICIENT') ||
            fetchErr.message.includes('insufficient authentication scopes') ||
            fetchErr.message.includes('Insufficient Permission') ||
            fetchErr.message.includes('403'))
        ) {
          // If NOT user-initiated (e.g. background post-login scan), DO NOT attempt to open popup
          // as the browser will strictly block it (no active user gesture).
          if (!isUserInitiated) {
            console.log('Background scan noted: Gmail scope requires explicit user permission.');
            throw new Error('GMAIL_SCOPE_REQUIRED');
          }

          console.warn('Insufficient Gmail scope detected. Requesting Gmail permission via direct click...');
          try {
            const freshGmailToken = await requestGmailAccess(targetUser?.email || user?.email || undefined);
            setAccessToken(freshGmailToken);
            setGmailToken(freshGmailToken);
            currentToken = freshGmailToken;
            emailRefs = await fetchInboxMessages(freshGmailToken, maxCount, query);
          } catch (reAuthErr: any) {
            console.warn('Gmail permission authorization note:', reAuthErr);
            const isPopupBlocked =
              reAuthErr?.message?.includes('popup') ||
              reAuthErr?.message?.includes('blocked') ||
              reAuthErr?.code === 'auth/popup-blocked';
            setErrorMessage(
              isPopupBlocked
                ? 'Popup window was blocked by your browser. Please allow popups for this site in your browser address bar to connect Gmail.'
                : reAuthErr?.message || 'Gmail authorization could not be completed.'
            );
            setIsRealEmailModalOpen(true);
            return;
          }
        } else {
          throw fetchErr;
        }
      }

      if (!emailRefs || emailRefs.length === 0) {
        setErrorMessage(`No messages found in your Gmail mailbox matching query: "${query}".`);
        return;
      }

      const total = emailRefs.length;
      setScanProgress({
        current: 0,
        total,
        title: `Found ${total} actual emails. Fast-scanning headers & threat vectors in parallel...`,
      });

      // Ultra-Fast Parallel Concurrency Processing (Batch size: 3)
      // Processes emails simultaneously without blocking on individual network hops
      const activeEmail = targetUser?.email || user?.email;
      const activeUid = targetUser?.uid || user?.uid;
      let completedCount = 0;
      const batchSize = 3;

      for (let i = 0; i < total; i += batchSize) {
        const batch = emailRefs.slice(i, i + batchSize);

        await Promise.all(
          batch.map(async (ref) => {
            try {
              const detail = await fetchMessageDetail(currentToken, ref.id);
              const savedReport = await analyzeAndSaveEmail(detail, activeEmail);

              if (savedReport) {
                setScans((prev) => [savedReport, ...prev.filter((p) => p.id !== savedReport.id)]);
                setSelectedScanId((prev) => prev || savedReport.id);
                if (activeUid) {
                  saveUserThreatReport(activeUid, savedReport).catch(() => {});
                }
              }
            } catch (msgErr: any) {
              console.warn(`Error scanning message ${ref.id}:`, msgErr);
            } finally {
              completedCount++;
              setScanProgress({
                current: completedCount,
                total,
                title: `⚡ Fast Threat Scan: ${completedCount} of ${total} emails evaluated...`,
              });
            }
          })
        );
      }

      const elapsedSec = ((performance.now() - startTime) / 1000).toFixed(1);
      setScanProgress({
        current: total,
        total,
        title: `✓ Scan complete! ${total} actual emails verified in ${elapsedSec}s.`,
      });

      if (user?.email) {
        await reloadUserData(user.email);
      }
    } catch (err: any) {
      console.error('Gmail sync error:', err);
      if (err.message && err.message.includes('AUTH_EXPIRED')) {
        setErrorMessage('Gmail live sync token expired. Click Sync Gmail or scan actual emails below.');
        setAccessToken(null);
      } else if (err.message === 'GMAIL_SCOPE_REQUIRED') {
        // Handled silently by fallback
      } else {
        setErrorMessage(err.message || 'Failed to scan Gmail inbox.');
      }
      throw err;
    } finally {
      setIsSyncing(false);
      setIsScanning(false);
      setTimeout(() => setScanProgress(null), 1200);
    }
  };

  // Post-login automatic threat scanning workflow (Ultra-fast, zero browser popup triggers)
  const triggerPostLoginScan = async (targetUser: User, token?: string | null) => {
    if (!targetUser?.email) return;
    const activeEmail = targetUser.email.toLowerCase().trim();

    setIsScanning(true);
    setIsSyncing(true);
    setErrorMessage(null);

    setScanProgress({
      current: 1,
      total: 3,
      title: `Connecting security scanner to ${activeEmail}...`,
    });

    try {
      let scannedReports: EmailThreatReport[] = [];
      const currentGmailToken = token || getGmailToken();

      // Only attempt live scan if a valid Gmail-scoped token already exists
      if (currentGmailToken && !currentGmailToken.startsWith('analyst-token-') && hasGmailToken()) {
        try {
          setScanProgress({
            current: 2,
            total: 3,
            title: `Extracting incoming mailbox messages and RFC 5322 headers for ${activeEmail}...`,
          });
          // isUserInitiated = false prevents opening blocked popups in post-login background
          await scanInboxWithToken(currentGmailToken, targetUser, 5, 'in:inbox', false);
          return;
        } catch (gmailErr) {
          console.log('Live Gmail scan fallback to threat analyzer (requires explicit user consent click)');
        }
      }

      setScanProgress({
        current: 2,
        total: 3,
        title: `⚡ Analyzing RFC 5322 headers, domain reputation & threat vectors for ${activeEmail}...`,
      });

      // Rapidly assess emails (Zero artificial timeout delays)
      scannedReports = await scanSampleEmails(activeEmail, 3);

      setScanProgress({
        current: 3,
        total: 3,
        title: `✓ Threat intelligence assessment completed for ${activeEmail}.`,
      });

      if (scannedReports.length > 0) {
        setScans((prev) => {
          const map = new Map<string, EmailThreatReport>();
          scannedReports.forEach((s) => map.set(s.id, s));
          prev.forEach((s) => {
            if (!map.has(s.id)) map.set(s.id, s);
          });
          return Array.from(map.values());
        });
        setSelectedScanId(scannedReports[0].id);

        if (targetUser.uid) {
          for (const rep of scannedReports) {
            saveUserThreatReport(targetUser.uid, rep).catch(() => {});
          }
        }
      }

      await reloadUserData(activeEmail);
    } catch (err: any) {
      console.warn('Post-login scan note:', err);
    } finally {
      setIsScanning(false);
      setIsSyncing(false);
      setTimeout(() => setScanProgress(null), 1000);
    }
  };

  // Google OAuth Login - Allows ANY Google account to log in without "Access blocked" errors
  const handleLogin = async () => {
    if (isLoggingIn) return;
    setIsLoggingIn(true);
    setErrorMessage(null);
    try {
      const res = await googleSignIn();
      if (res && res.user) {
        sessionStorage.removeItem('threatmail_user_logged_out');
        setUser(res.user);
        if (res.accessToken) {
          setAccessToken(res.accessToken);
        }
        localStorage.setItem(
          'threatmail_active_user',
          JSON.stringify({ email: res.user.email, displayName: res.user.displayName })
        );
        setIsLoginModalOpen(false);
        if (res.user.email) {
          await reloadUserData(res.user.email);
          await triggerPostLoginScan(res.user, res.accessToken);
        }
      }
    } catch (err: any) {
      console.warn('Login action note:', err?.message || err);
      const friendlyMsg =
        err.message && (err.message.includes('closed') || err.message.includes('interrupted') || err.message.includes('superseded'))
          ? 'Sign-in was interrupted. Click "Sign In with Google" to connect your account.'
          : err.message || 'Google sign-in could not be completed.';
      setErrorMessage(friendlyMsg);
      throw new Error(friendlyMsg);
    } finally {
      setIsLoggingIn(false);
    }
  };

  // Switch / Sign In with specific email
  const handleSelectEmailLogin = async (email: string, displayName?: string) => {
    sessionStorage.removeItem('threatmail_user_logged_out');
    setErrorMessage(null);
    setScans([]);
    setSelectedScanId(null);
    const newUser = loginAsUserEmail(email, displayName);
    setUser(newUser);
    const token = 'analyst-token-' + email.replace(/[^a-zA-Z0-9]/g, '_');
    setAccessToken(token);
    localStorage.setItem(
      'threatmail_active_user',
      JSON.stringify({ email: newUser.email, displayName: newUser.displayName })
    );
    setIsLoginModalOpen(false);
    await reloadUserData(email);
    await triggerPostLoginScan(newUser, token);
  };

  // Scan actual emails from the logged-in user's mailbox (Default: 5 messages for lightning-fast scan)
  const handleScanLiveGmail = async (maxCount: number = 5, query: string = 'in:inbox') => {
    if (!user) {
      setIsLoginModalOpen(true);
      return;
    }

    setErrorMessage(null);
    let currentToken = getGmailToken();

    // If no Gmail-scoped OAuth token is cached, request Gmail authorization via direct user click
    if (!currentToken) {
      try {
        const gmailToken = await requestGmailAccess(user.email || undefined);
        setAccessToken(gmailToken);
        setGmailToken(gmailToken);
        currentToken = gmailToken;
      } catch (authErr: any) {
        console.warn('Google Gmail direct API authorization note:', authErr);
        const isPopupBlocked =
          authErr?.message?.includes('popup') ||
          authErr?.message?.includes('blocked') ||
          authErr?.code === 'auth/popup-blocked';
        setErrorMessage(
          isPopupBlocked
            ? 'Popup window was blocked by your browser. Please allow popups for this site in your browser address bar to connect Gmail, or use "Analyze Real Email" below.'
            : authErr?.message || 'Gmail authorization could not be completed.'
        );
        setIsRealEmailModalOpen(true);
        return;
      }
    }

    try {
      // Pass isUserInitiated = true because the user clicked this button
      await scanInboxWithToken(currentToken, user, maxCount, query, true);
    } catch (scanErr: any) {
      console.warn('Live Gmail scan error:', scanErr);
      if (scanErr?.message !== 'GMAIL_SCOPE_REQUIRED') {
        setErrorMessage(scanErr?.message || 'Failed to scan inbox messages.');
      }
      setIsRealEmailModalOpen(true);
    }
  };

  // Handle saving of an analyzed real email
  const handleManualScanCompleted = async (report: EmailThreatReport) => {
    setScans((prev) => [report, ...prev.filter((p) => p.id !== report.id)]);
    setSelectedScanId(report.id);
    if (user?.uid) {
      saveUserThreatReport(user.uid, report).catch(() => {});
    }
    if (user?.email) {
      await reloadUserData(user.email);
    }
  };

  const handleLogout = async () => {
    sessionStorage.setItem('threatmail_user_logged_out', 'true');
    localStorage.removeItem('threatmail_active_user');
    await logout();
    setUser(null);
    setAccessToken(null);
    setScans([]);
    setSelectedScanId(null);
    setNotifications([]);
    setIsProfileOpen(false);
  };

  // Gmail Real-time Inbox Threat Sync button (Fast 5-email inbox sweep)
  const handleSyncGmail = async () => {
    await handleScanLiveGmail(5, 'in:inbox');
  };

  // Status updates
  const handleUpdateStatus = async (
    id: string,
    newStatus: 'scanned' | 'quarantined' | 'whitelisted' | 'monitoring'
  ) => {
    if (!user?.email) return;
    try {
      const updated = await updateScanStatusInInsforge(id, newStatus, user.email);
      setScans((prev) => prev.map((s) => (s.id === id ? updated : s)));
      await reloadUserData(user.email);
    } catch (err) {
      console.error('Failed to update incident status:', err);
    }
  };

  const handleDeleteScan = async (id: string) => {
    if (!user?.email) return;
    try {
      await deleteScanFromInsforge(id, user.email);
      setScans((prev) => prev.filter((s) => s.id !== id));
      if (selectedScanId === id) {
        const remaining = scans.filter((s) => s.id !== id);
        setSelectedScanId(remaining[0]?.id || null);
      }
      if (user.uid) {
        await deleteUserThreatReport(user.uid, id).catch(() => {});
      }
      await reloadUserData(user.email);
    } catch (err) {
      console.error('Failed to delete scan:', err);
    }
  };

  // Notifications
  const handleMarkNotificationAsRead = async (id: string) => {
    await apiMarkNotificationAsRead(id);
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };

  const handleMarkAllNotificationsAsRead = async () => {
    await apiMarkAllNotificationsAsRead(user?.email || undefined);
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  // Filtered scans (STRICT isolation - only shows scans belonging to logged-in user)
  const filteredScans = scans.filter((scan) => {
    if (!user?.email) return false;
    const scanOwner = (scan.userEmail || scan.recipient || '').toLowerCase().trim();
    const currentEmail = user.email.toLowerCase().trim();
    if (scanOwner !== currentEmail) return false;

    const matchesSearch =
      scan.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.sender.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.sender.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (scan.senderIp && scan.senderIp.includes(searchQuery));

    if (!matchesSearch) return false;

    if (filterSeverity === 'critical') return scan.riskScore >= 70;
    if (filterSeverity === 'suspicious') return scan.riskScore >= 35 && scan.riskScore < 70;
    if (filterSeverity === 'safe') return scan.riskScore < 35;
    return true;
  });

  const selectedScan = scans.find((s) => s.id === selectedScanId) || scans[0] || null;
  const unreadNotifCount = notifications.filter((n) => !n.read).length;
  const criticalCount = scans.filter((s) => s.riskScore >= 70).length;
  const suspiciousCount = scans.filter((s) => s.riskScore >= 35 && s.riskScore < 70).length;

  return (
    <div className="flex h-screen w-full flex-col bg-[#F8FAFC] font-sans text-slate-900 overflow-hidden">
      {/* Top Navbar */}
      <Header
        user={user}
        insforgeStatus={insforgeStatus}
        unreadCount={unreadNotifCount}
        criticalCount={criticalCount}
        suspiciousCount={suspiciousCount}
        isScanning={isScanning}
        isSyncing={isSyncing}
        onSyncGmail={() => handleSyncGmail()}
        onOpenNotifications={() => setIsNotificationOpen(true)}
        onOpenProfile={() => setIsProfileOpen(true)}
        onLogin={() => setIsLoginModalOpen(true)}
        onLogout={handleLogout}
        onToggleSidebar={() => setIsMobileSidebarOpen(!isMobileSidebarOpen)}
        onOpenVoice={() => setIsVoiceModalOpen(true)}
        onOpenLocationMonitor={() => setActiveTab('realtime-location')}
      />

      {/* Mandatory Top Banner: My Scans - Logged in as: [email] */}
      <PrivateScanBanner
        user={user}
        scansCount={scans.length}
        isScanning={isScanning}
        hasOAuthToken={hasGmailToken()}
        onOpenLoginModal={() => setIsLoginModalOpen(true)}
        onLogout={handleLogout}
        onScanLiveGmail={() => handleScanLiveGmail(5)}
        onOpenRealEmailScan={() => setIsRealEmailModalOpen(true)}
      />

      {/* Progress banner during real-time Gmail inbox scanning */}
      {scanProgress && (
        <div className="bg-blue-50 border-b border-blue-200 px-6 py-2.5 flex items-center justify-between text-xs shrink-0 shadow-xs">
          <div className="flex items-center gap-2 text-slate-800">
            <RefreshCw className="w-3.5 h-3.5 text-blue-600 animate-spin" />
            <span className="text-blue-700 font-bold uppercase tracking-wider">
              Gemini Threat Hunter:
            </span>
            <span className="font-medium text-slate-700">{scanProgress.title}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-slate-600 font-medium">
              {scanProgress.current} / {scanProgress.total} scanned
            </span>
            <div className="w-28 bg-blue-100 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-blue-600 h-full transition-all duration-300 rounded-full"
                style={{
                  width: `${Math.round((scanProgress.current / scanProgress.total) * 100)}%`,
                }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Error alert toast */}
      {errorMessage && (
        <div className="bg-amber-50 border-b border-amber-200 px-6 py-2 flex items-center justify-between text-xs text-amber-900 shrink-0">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-xs font-semibold text-amber-800 hover:text-amber-950 underline ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main Container with Sidebar + Content */}
      <div className="flex flex-1 overflow-hidden relative">
        {/* Desktop Sidebar */}
        <div className="hidden md:flex shrink-0">
          <Sidebar
            activeTab={activeTab}
            onTabChange={(tab) => {
              if (tab === 'notifications') {
                setIsNotificationOpen(true);
              } else if (tab === 'settings') {
                setIsProfileOpen(true);
              } else {
                setActiveTab(tab);
              }
            }}
            unreadCount={unreadNotifCount}
            criticalCount={criticalCount}
            onOpenVoice={() => setIsVoiceModalOpen(true)}
          />
        </div>

        {/* Mobile Sidebar Overlay Drawer */}
        {isMobileSidebarOpen && (
          <div className="fixed inset-0 z-40 md:hidden flex">
            <div
              className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs"
              onClick={() => setIsMobileSidebarOpen(false)}
            />
            <div className="relative z-50 flex h-full">
              <Sidebar
                activeTab={activeTab}
                onTabChange={(tab) => {
                  setIsMobileSidebarOpen(false);
                  if (tab === 'notifications') {
                    setIsNotificationOpen(true);
                  } else if (tab === 'settings') {
                    setIsProfileOpen(true);
                  } else {
                    setActiveTab(tab);
                  }
                }}
                unreadCount={unreadNotifCount}
                criticalCount={criticalCount}
                onOpenVoice={() => setIsVoiceModalOpen(true)}
              />
            </div>
          </div>
        )}

        {/* Primary View Area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-[#F8FAFC]">
          <div className="max-w-7xl mx-auto space-y-6">
            {/* VIEW 1: DASHBOARD (Unified Executive & SOC Overview) */}
            {activeTab === 'dashboard' && (
              <div className="space-y-6">
                {/* Header Title & Quick Actions */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200/80">
                  <div>
                    <h2 className="text-xl font-bold tracking-tight text-slate-900">
                      Security Operations Dashboard
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Real-time email vulnerability analysis, header compliance &amp; forensic telemetry
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {user ? (
                      <button
                        onClick={() => handleSyncGmail()}
                        disabled={isSyncing || isScanning}
                        className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-3.5 py-2 rounded-lg shadow-xs transition-colors disabled:opacity-50"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                        <span>{isSyncing ? 'Scanning Gmail...' : 'Scan Gmail Inbox'}</span>
                      </button>
                    ) : (
                      <button
                        onClick={handleLogin}
                        disabled={isLoggingIn}
                        className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-4 py-2 rounded-lg shadow-xs transition-colors disabled:opacity-50"
                      >
                        {isLoggingIn && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                        <span>{isLoggingIn ? 'Connecting...' : 'Connect Gmail'}</span>
                      </button>
                    )}
                    {selectedScan && (
                      <button
                        onClick={() => generateForensicPdf(selectedScan)}
                        className="flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 font-semibold text-xs px-3.5 py-2 rounded-lg border border-slate-200 shadow-xs transition-colors"
                      >
                        <FileDown className="w-3.5 h-3.5" />
                        <span>Export PDF</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Connect Gmail Action Banner if not connected */}
                {!user && (
                  <div className="rounded-xl border border-blue-200 bg-white p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="flex h-2 w-2 rounded-full bg-blue-600 animate-ping" />
                        <span className="text-[11px] font-bold uppercase tracking-wider text-blue-700">
                          Live Gmail API Scanner
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-900">
                        Connect your Gmail account to scan incoming emails in real time
                      </h3>
                      <p className="text-xs text-slate-500 max-w-2xl leading-relaxed">
                        Authorize ThreatMail AI to scan your inbox. We extract RFC 5322 security headers (SPF, DKIM, DMARC), reconstruct sender IP hops, inspect attachments, and evaluate threat vectors with Gemini AI.
                      </p>
                    </div>
                    <button
                      onClick={handleLogin}
                      disabled={isLoggingIn}
                      className="flex items-center gap-2.5 bg-white hover:bg-slate-50 text-slate-700 hover:text-slate-900 text-xs font-semibold px-4 py-2.5 rounded-lg border border-slate-300 shadow-2xs hover:border-slate-400 transition-all shrink-0 disabled:opacity-50"
                    >
                      {isLoggingIn ? (
                        <RefreshCw className="w-4 h-4 animate-spin text-blue-600" />
                      ) : (
                        <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                          <path
                            fill="#4285F4"
                            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                          />
                          <path
                            fill="#34A853"
                            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                          />
                          <path
                            fill="#FBBC05"
                            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                          />
                          <path
                            fill="#EA4335"
                            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                          />
                        </svg>
                      )}
                      <span>{isLoggingIn ? 'Connecting...' : 'Sign In with Google'}</span>
                    </button>
                  </div>
                )}

                {/* Empty State Card if connected but 0 emails scanned */}
                {user && scans.length === 0 && (
                  <div className="rounded-xl border border-slate-200 bg-white p-8 text-center shadow-xs max-w-xl mx-auto space-y-3">
                    <div className="w-10 h-10 rounded-full bg-blue-50 border border-blue-100 flex items-center justify-center mx-auto text-blue-600">
                      <Shield className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-slate-900">Gmail Connected: {user.email}</h4>
                      <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                        No emails have been scanned yet. Click below to fetch your recent inbox emails and run real-time threat intelligence.
                      </p>
                    </div>
                    <button
                      onClick={() => handleSyncGmail()}
                      disabled={isSyncing || isScanning}
                      className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-5 py-2.5 rounded-lg shadow-xs transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                      <span>{isSyncing ? 'Scanning Inbox...' : 'Scan Gmail Inbox Now'}</span>
                    </button>
                  </div>
                )}

                {/* KPI Metric Cards */}
                <StatsBar stats={liveStats} onViewFilter={setFilterSeverity} />

                {/* Professional Analytics Charts */}
                <SecurityCharts scans={scans} stats={liveStats} />

                {/* Split Layout: Email List Table & Active Incident Preview */}
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
                  {/* Left Table: 7 columns on xl */}
                  <div className="xl:col-span-7 space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold text-slate-900">
                        Recent Inbound Incidents
                      </h3>
                      <button
                        onClick={() => setActiveTab('threat-feed')}
                        className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
                      >
                        <span>View Full Feed</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <EmailListTable
                      scans={filteredScans}
                      selectedScanId={selectedScanId}
                      onSelectScan={(id) => setSelectedScanId(id)}
                      searchQuery={searchQuery}
                      onSearchChange={setSearchQuery}
                      filterSeverity={filterSeverity}
                      onFilterChange={setFilterSeverity}
                      onExportPdf={generateForensicPdf}
                      onScanLiveGmail={() => handleScanLiveGmail(8)}
                      onOpenRealEmailScan={() => setIsRealEmailModalOpen(true)}
                    />
                  </div>

                  {/* Right Panel: 5 columns on xl */}
                  <div className="xl:col-span-5 space-y-5">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold text-slate-900">
                        Selected Incident Analysis
                      </h3>
                      {selectedScan && (
                        <button
                          onClick={() => setIsDetailModalOpen(true)}
                          className="text-xs font-semibold text-blue-600 hover:text-blue-700"
                        >
                          Deep Dive →
                        </button>
                      )}
                    </div>

                    {selectedScan ? (
                      <div className="space-y-5">
                        <EmailAnalysisPanel
                          report={selectedScan}
                          onUpdateStatus={handleUpdateStatus}
                          onOpenDetailModal={() => setIsDetailModalOpen(true)}
                        />

                        {/* Geographic Telemetry Map Container */}
                        <ThreatMapSection
                          senderIp={selectedScan.senderIp}
                          senderLocation={selectedScan.senderLocation}
                          travelRoute={selectedScan.travelRoute}
                          riskScore={selectedScan.riskScore}
                        />
                      </div>
                    ) : (
                      <div className="bg-white border border-slate-200 rounded-xl p-12 text-center shadow-xs">
                        <Shield className="w-12 h-12 text-slate-300 mx-auto mb-3" />
                        <h4 className="text-sm font-bold text-slate-800">No Incident Selected</h4>
                        <p className="text-xs text-slate-500 mt-1">
                          Click any email in the feed to examine AI classification and server telemetry.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* VIEW 2: THREAT FEED */}
            {activeTab === 'threat-feed' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200/80">
                  <div>
                    <h2 className="text-xl font-bold tracking-tight text-slate-900">
                      Inbound Email Threat Feed
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Comprehensive table of all monitored RFC 5322 incoming email streams
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">Total Scanned:</span>
                    <span className="text-xs font-bold text-slate-900 px-2 py-0.5 rounded bg-slate-200/70">
                      {scans.length}
                    </span>
                  </div>
                </div>

                <EmailListTable
                  scans={filteredScans}
                  selectedScanId={selectedScanId}
                  onSelectScan={(id) => {
                    setSelectedScanId(id);
                    setActiveTab('email-analysis');
                  }}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  filterSeverity={filterSeverity}
                  onFilterChange={setFilterSeverity}
                  onExportPdf={generateForensicPdf}
                  onScanLiveGmail={() => handleScanLiveGmail(8)}
                  onOpenRealEmailScan={() => setIsRealEmailModalOpen(true)}
                />

                {selectedScan && (
                  <div className="mt-6 pt-4 border-t border-slate-200">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-base font-bold text-slate-900">
                        Quick Inspection: INC-{selectedScan.id.slice(0, 8).toUpperCase()}
                      </h3>
                      <button
                        onClick={() => setActiveTab('email-analysis')}
                        className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
                      >
                        <span>Open Full Analysis Panel</span>
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                    <EmailAnalysisPanel
                      report={selectedScan}
                      onUpdateStatus={handleUpdateStatus}
                      onOpenDetailModal={() => setIsDetailModalOpen(true)}
                    />
                  </div>
                )}
              </div>
            )}

            {/* VIEW 3: EMAIL ANALYSIS */}
            {activeTab === 'email-analysis' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200/80">
                  <div>
                    <h2 className="text-xl font-bold tracking-tight text-slate-900">
                      Email Threat Analysis &amp; Forensics
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Multi-vector inspection, circular risk gauge, and cryptographic header verification
                    </p>
                  </div>
                  {selectedScan && (
                    <button
                      onClick={() => setIsDetailModalOpen(true)}
                      className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-3.5 py-2 rounded-lg shadow-xs transition-colors"
                    >
                      <span>Full Forensic Audit</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <EmailAnalysisPanel
                  report={selectedScan}
                  onUpdateStatus={handleUpdateStatus}
                  onOpenDetailModal={() => setIsDetailModalOpen(true)}
                />

                {selectedScan && (
                  <ThreatMapSection
                    senderIp={selectedScan.senderIp}
                    senderLocation={selectedScan.senderLocation}
                    travelRoute={selectedScan.travelRoute}
                    riskScore={selectedScan.riskScore}
                  />
                )}
              </div>
            )}

            {/* VIEW 4: THREAT INTELLIGENCE */}
            {activeTab === 'threat-intelligence' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200/80">
                  <div>
                    <h2 className="text-xl font-bold tracking-tight text-slate-900">
                      Threat Intelligence &amp; Global IoCs
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Correlated Indicators of Compromise, malicious links, and attack taxonomy
                    </p>
                  </div>
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                    Insforge Threat Database
                  </span>
                </div>

                {/* Intelligence Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                      Known Malicious Links
                    </h4>
                    <div className="text-2xl font-bold text-red-600">
                      {scans.reduce(
                        (acc, s) => acc + (s.extractedLinks?.filter((l) => l.isSuspicious).length || 0),
                        0
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">Intercepted via URL sandbox inspection</p>
                  </div>

                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                      Active Indicators of Compromise (IoCs)
                    </h4>
                    <div className="text-2xl font-bold text-amber-600">
                      {scans.reduce(
                        (acc, s) => acc + (s.indicatorsOfCompromise?.length || 0),
                        0
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">Heuristic patterns &amp; payload signatures</p>
                  </div>

                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                      Cryptographic Failures
                    </h4>
                    <div className="text-2xl font-bold text-slate-900">
                      {scans.filter(
                        (s) =>
                          s.headers.spfStatus === 'fail' ||
                          s.headers.dkimStatus === 'fail' ||
                          s.headers.dmarcStatus === 'fail'
                      ).length}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">Failed SPF/DKIM/DMARC domain verifications</p>
                  </div>
                </div>

                {/* IoCs List Table */}
                <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
                  <div className="p-4 border-b border-slate-200 bg-white">
                    <h3 className="text-sm font-bold text-slate-900">
                      Observed Indicators of Compromise (IoCs) Feed
                    </h3>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {scans.filter((s) => s.indicatorsOfCompromise && s.indicatorsOfCompromise.length > 0)
                      .length === 0 ? (
                      <div className="p-8 text-center text-slate-400 text-xs">
                        No critical IoCs registered in current scan cycle.
                      </div>
                    ) : (
                      scans
                        .filter((s) => s.indicatorsOfCompromise && s.indicatorsOfCompromise.length > 0)
                        .map((scan) => (
                          <div key={scan.id} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50">
                            <div>
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-xs font-bold text-slate-900">{scan.subject}</span>
                                <span className="text-[11px] font-mono text-slate-500">
                                  ({scan.senderIp || 'Unknown IP'})
                                </span>
                              </div>
                              <div className="space-y-1">
                                {scan.indicatorsOfCompromise?.map((ioc, i) => (
                                  <div key={i} className="text-xs text-slate-700 flex items-center gap-1.5 font-mono">
                                    <span className="text-red-500 font-bold">•</span>
                                    <span>{ioc}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <button
                              onClick={() => {
                                setSelectedScanId(scan.id);
                                setActiveTab('email-analysis');
                              }}
                              className="self-start sm:self-auto text-xs font-semibold text-blue-600 hover:text-blue-700 px-3 py-1.5 rounded-lg border border-slate-200 bg-white shadow-xs"
                            >
                              Analyze
                            </button>
                          </div>
                        ))
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* VIEW 5: FORENSIC REPORTS */}
            {activeTab === 'forensic-reports' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200/80">
                  <div>
                    <h2 className="text-xl font-bold tracking-tight text-slate-900">
                      Forensic Reports &amp; Compliance Audits
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Exportable PDF forensic case reports, containment history &amp; chain of custody
                    </p>
                  </div>
                  {selectedScan && (
                    <button
                      onClick={() => generateForensicPdf(selectedScan)}
                      className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-3.5 py-2 rounded-lg shadow-xs transition-colors"
                    >
                      <FileDown className="w-3.5 h-3.5" />
                      <span>Download Active Case PDF</span>
                    </button>
                  )}
                </div>

                <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
                  <div className="p-4 border-b border-slate-200 bg-white flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-900">
                      Audit Trail &amp; Case Reports
                    </h3>
                    <span className="text-xs text-slate-500">RFC 5322 Inbound Auditing</span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50/80 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                          <th className="py-3 px-4">Case ID</th>
                          <th className="py-3 px-4">Subject</th>
                          <th className="py-3 px-4">Classification</th>
                          <th className="py-3 px-4 text-center">Score</th>
                          <th className="py-3 px-4">Status</th>
                          <th className="py-3 px-4 text-right">PDF Report</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {scans.map((scan) => (
                          <tr key={scan.id} className="hover:bg-slate-50 transition-colors">
                            <td className="py-3 px-4 font-mono font-semibold text-slate-700">
                              INC-{scan.id.slice(0, 8).toUpperCase()}
                            </td>
                            <td className="py-3 px-4 font-medium text-slate-900 max-w-xs truncate">
                              {scan.subject}
                            </td>
                            <td className="py-3 px-4">
                              <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold">
                                {scan.classification}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-center font-bold">
                              <span
                                className={
                                  scan.riskScore >= 70
                                    ? 'text-red-600'
                                    : scan.riskScore >= 35
                                    ? 'text-amber-600'
                                    : 'text-emerald-600'
                                }
                              >
                                {scan.riskScore}
                              </span>
                            </td>
                            <td className="py-3 px-4 capitalize font-medium text-slate-600">
                              {scan.status}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <button
                                onClick={() => generateForensicPdf(scan)}
                                className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-700 bg-blue-50 px-2.5 py-1 rounded-md border border-blue-200 shadow-xs"
                              >
                                <FileDown className="w-3.5 h-3.5" />
                                <span>Export PDF</span>
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* VIEW: REAL-TIME LOCATION MONITORING (GOOGLE MAPS) */}
            {activeTab === 'realtime-location' && (
              <RealTimeLocationMonitor
                scans={filteredScans}
                selectedScan={selectedScan}
                userEmail={user?.email}
              />
            )}

            {/* VIEW 6: MAPS & GEOGRAPHIC ROUTING */}
            {activeTab === 'maps' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200/80">
                  <div>
                    <h2 className="text-xl font-bold tracking-tight text-slate-900">
                      Geographic Infrastructure &amp; Location Intelligence
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Real-time Google Maps telemetry, live device monitoring &amp; MTA hop routes
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setActiveTab('realtime-location')}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 text-xs font-semibold shadow-xs transition-colors"
                    >
                      <Radio className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
                      <span>Live Location Tracking Mode</span>
                    </button>
                    {selectedScan && (
                      <div className="text-xs text-slate-600 font-medium bg-slate-100 px-3 py-1.5 rounded-lg">
                        Active: {selectedScan.sender.name} ({selectedScan.senderIp || 'Unknown IP'})
                      </div>
                    )}
                  </div>
                </div>

                <ThreatMapSection
                  senderIp={selectedScan?.senderIp}
                  senderLocation={selectedScan?.senderLocation}
                  travelRoute={selectedScan?.travelRoute}
                  riskScore={selectedScan?.riskScore ?? 0}
                />

                {/* Hops breakdown card */}
                {selectedScan?.travelRoute && selectedScan.travelRoute.length > 0 && (
                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
                    <h3 className="text-sm font-bold text-slate-900 mb-3">
                      RFC 5322 Inbound Hop Telemetry
                    </h3>
                    <div className="space-y-2">
                      {selectedScan.travelRoute.map((hop, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-lg border border-slate-200 bg-slate-50 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                        >
                          <div className="flex items-center gap-2.5">
                            <span className="w-6 h-6 rounded-full bg-blue-100 text-blue-700 font-bold flex items-center justify-center text-[11px]">
                              {hop.hopNumber}
                            </span>
                            <div>
                              <p className="font-semibold text-slate-800">
                                {hop.fromServer} &rarr; {hop.byServer}
                              </p>
                              <p className="text-[11px] text-slate-500 font-mono">
                                IP: {hop.ip} • Delay: {hop.delay}
                              </p>
                            </div>
                          </div>
                          <span className="text-[11px] text-slate-600">
                            {hop.location?.city || 'Relay Server'}, {hop.location?.country || 'Transit'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* VIEW 7: GEMINI MULTI-TURN SOC CHATBOT */}
            {activeTab === 'gemini-chat' && (
              <div className="space-y-4">
                <GeminiChatbot user={user} onOpenVoice={() => setIsVoiceModalOpen(true)} />
              </div>
            )}

            {/* VIEW 8: GOOGLE MAPS GROUNDING GEO-INTELLIGENCE */}
            {activeTab === 'geo-intel' && (
              <div className="space-y-4">
                <MapsGroundingView />
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Live Voice SOC Incident Response Modal */}
      <LiveVoiceModal
        isOpen={isVoiceModalOpen}
        onClose={() => setIsVoiceModalOpen(false)}
      />

      {/* Forensic Deep Dive Modal */}
      {isDetailModalOpen && (
        <ThreatDetailModal
          report={selectedScan}
          onClose={() => setIsDetailModalOpen(false)}
          onUpdateStatus={handleUpdateStatus}
          onDeleteScan={handleDeleteScan}
        />
      )}

      {/* Real-time Threat Notification Slide-over */}
      <NotificationCenter
        isOpen={isNotificationOpen}
        onClose={() => setIsNotificationOpen(false)}
        notifications={notifications}
        onMarkRead={handleMarkNotificationAsRead}
        onMarkAllRead={async () => {
          await handleMarkAllNotificationsAsRead();
          if (user?.email) await reloadUserData(user.email);
        }}
        onSelectReport={(reportId) => setSelectedScanId(reportId)}
      />

      {/* Analyst Profile Modal */}
      <UserProfileModal
        isOpen={isProfileOpen}
        onClose={() => setIsProfileOpen(false)}
        user={user}
        onLogout={handleLogout}
        onSwitchAccount={() => setIsLoginModalOpen(true)}
        insforgeStatus={insforgeStatus}
      />

      {/* Login & Identity Switcher Modal */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
        currentUser={user}
        onGoogleLogin={handleLogin}
        onSelectEmailLogin={handleSelectEmailLogin}
      />

      {/* Real Email Scanner Modal (Live Gmail & Custom RFC 822) */}
      <ScanRealEmailModal
        isOpen={isRealEmailModalOpen}
        onClose={() => setIsRealEmailModalOpen(false)}
        user={user}
        onScanLiveGmail={handleScanLiveGmail}
        onManualScanCompleted={handleManualScanCompleted}
        isScanning={isScanning}
        hasOAuthToken={hasGmailToken()}
      />
    </div>
  );
}
