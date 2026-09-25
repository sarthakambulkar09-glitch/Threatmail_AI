import React, { useState, useEffect, useRef } from 'react';
import { User } from 'firebase/auth';
import {
  Send,
  Bot,
  User as UserIcon,
  Sparkles,
  RefreshCw,
  MapPin,
  ExternalLink,
  Zap,
  Shield,
  Search,
  CheckCircle2,
  Trash2,
  HelpCircle,
  AlertCircle,
  Mic,
} from 'lucide-react';
import {
  saveUserChatMessage,
  subscribeUserChatMessages,
  clearUserChatMessages,
  PersistedChatMessage,
} from '../insforge/databaseService';

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  content: string;
  model?: string;
  timestamp: string;
  groundingLinks?: { title: string; uri: string; sourceType?: string; snippet?: string }[];
}

interface GeminiChatbotProps {
  user: User | null;
  onOpenVoice?: () => void;
}

export const GeminiChatbot: React.FC<GeminiChatbotProps> = ({ user, onOpenVoice }) => {
  // Model & Role State
  const [selectedRole, setSelectedRole] = useState<'general' | 'forensic' | 'fast' | 'geo'>('general');
  const [useMapsGrounding, setUseMapsGrounding] = useState<boolean>(false);
  const [inputMessage, setInputMessage] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Conversation history
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome-msg',
      role: 'model',
      content: `Hello! I am your **ThreatMail AI SOC Analyst**. I'm powered by Google Gemini to help you evaluate email threats, deconstruct malicious headers, inspect phishing links, and formulate response playbooks.
\nChoose a specialist mode above, or type an inquiry below to get started!`,
      model: 'gemini-3.5-flash',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  // Subscribe to persistent Firestore chat messages when user is signed in
  useEffect(() => {
    if (!user) return;

    const unsubscribe = subscribeUserChatMessages(user.uid, (firestoreMsgs) => {
      if (firestoreMsgs && firestoreMsgs.length > 0) {
        const formatted: ChatMessage[] = firestoreMsgs.map((m) => ({
          id: m.id,
          role: m.role as 'user' | 'model',
          content: m.text,
          model: m.model,
          timestamp: new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          groundingLinks: m.groundingLinks,
        }));
        setMessages(formatted);
      }
    });

    return () => unsubscribe();
  }, [user]);

  // Auto-scroll to bottom of message thread
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Model definition for current mode
  const getModelForRole = (role: string) => {
    switch (role) {
      case 'forensic':
        return {
          id: 'gemini-3.1-pro-preview',
          name: 'gemini-3.1-pro-preview',
          badge: 'Complex Forensic Reasoning',
          color: 'bg-purple-100 text-purple-800 border-purple-200',
        };
      case 'fast':
        return {
          id: 'gemini-3.1-flash-lite',
          name: 'gemini-3.1-flash-lite',
          badge: 'Fast Triage & Lookup',
          color: 'bg-emerald-100 text-emerald-800 border-emerald-200',
        };
      case 'geo':
      case 'general':
      default:
        return {
          id: 'gemini-3.5-flash',
          name: 'gemini-3.5-flash',
          badge: 'General SOC Analyst',
          color: 'bg-blue-100 text-blue-800 border-blue-200',
        };
    }
  };

  const currentModelInfo = getModelForRole(selectedRole);

  const handleSendMessage = async (customText?: string) => {
    const textToSend = customText || inputMessage.trim();
    if (!textToSend || isLoading) return;

    setError(null);
    const userMsgId = `user-${Date.now()}`;
    const userTimestamp = new Date().toISOString();

    const newMsg: ChatMessage = {
      id: userMsgId,
      role: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const updatedHistory = [...messages, newMsg];
    setMessages(updatedHistory);
    setInputMessage('');
    setIsLoading(true);

    // If logged in, persist user message in Firestore
    if (user) {
      saveUserChatMessage(user.uid, {
        id: userMsgId,
        userId: user.uid,
        role: 'user',
        model: currentModelInfo.id,
        text: textToSend,
        createdAt: userTimestamp,
      }).catch((e) => console.warn('Firestore chat save error:', e));
    }

    try {
      // Get location for Maps Grounding if enabled
      let userLocation: { latitude: number; longitude: number } | undefined;
      if (useMapsGrounding && navigator.geolocation) {
        try {
          const pos = await new Promise<GeolocationPosition>((resolve, reject) => {
            navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 4000 });
          });
          userLocation = {
            latitude: pos.coords.latitude,
            longitude: pos.coords.longitude,
          };
        } catch (locErr) {
          console.warn('Geolocation acquisition skipped:', locErr);
        }
      }

      // Convert conversation history for server multi-turn API
      const apiMessages = updatedHistory
        .filter((m) => m.id !== 'welcome-msg')
        .map((m) => ({
          role: m.role,
          content: m.content,
        }));

      const res = await fetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: apiMessages,
          roleId: selectedRole,
          modelOverride: currentModelInfo.id,
          enableMapsGrounding: useMapsGrounding,
          userLocation,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || `Server responded with status ${res.status}`);
      }

      const data = await res.json();
      const modelMsgId = `model-${Date.now()}`;
      const modelTimestamp = new Date().toISOString();

      const aiMsg: ChatMessage = {
        id: modelMsgId,
        role: 'model',
        content: data.text,
        model: data.model || currentModelInfo.id,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        groundingLinks: data.groundingLinks,
      };

      setMessages((prev) => [...prev, aiMsg]);

      // If logged in, persist model response in Firestore
      if (user) {
        saveUserChatMessage(user.uid, {
          id: modelMsgId,
          userId: user.uid,
          role: 'model',
          model: data.model || currentModelInfo.id,
          text: data.text,
          createdAt: modelTimestamp,
          groundingLinks: data.groundingLinks,
        }).catch((e) => console.warn('Firestore chat save error:', e));
      }
    } catch (err: any) {
      console.error('Chat generation error:', err);
      setError(err?.message || 'Failed to generate response from Gemini');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearHistory = async () => {
    if (user) {
      try {
        await clearUserChatMessages(user.uid);
      } catch (e) {
        console.warn('Error clearing Firestore chat:', e);
      }
    }
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: 'model',
        content: 'Conversation history cleared. Ready for a new investigation.',
        model: currentModelInfo.id,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  };

  const samplePrompts = [
    { label: 'Analyze SPF/DKIM Mismatch', text: 'How do I investigate an email where the SPF passes for one domain but the DKIM d= value points to a different domain?' },
    { label: 'Deobfuscate Obfuscated URL', text: 'Can you analyze how attackers use open redirects, URL shorteners, and unicode homoglyphs in phishing emails?' },
    { label: 'BEC Wire Fraud Playbook', text: 'What is the immediate response checklist for a suspected CEO fraudulent wire transfer email?' },
    { label: 'Check Nearby CERT Centers', text: 'Where are the accredited Computer Emergency Response Teams (CERT) and cybersecurity incident centers located in my region?' },
  ];

  return (
    <div className="flex flex-col h-[calc(100vh-8.5rem)] bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
      {/* Top Header & Role Selector Bar */}
      <div className="p-4 border-b border-slate-200 bg-slate-50/75 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-xs">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-900">Gemini SOC Assistant</h2>
              <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${currentModelInfo.color}`}>
                {currentModelInfo.badge}
              </span>
              {useMapsGrounding && (
                <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                  <MapPin className="w-3 h-3" />
                  Maps Grounding Active
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Multi-turn conversational cybersecurity intelligence powered by Google Gemini
            </p>
          </div>
        </div>

        {/* Action Controls & Role Selectors */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Role selector dropdown */}
          <div className="flex items-center rounded-lg bg-white border border-slate-200 p-1 text-xs shadow-2xs">
            <button
              onClick={() => {
                setSelectedRole('general');
                setUseMapsGrounding(false);
              }}
              className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                selectedRole === 'general' && !useMapsGrounding
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
              title="General SOC threat triage (gemini-3.5-flash)"
            >
              General SOC (3.5 Flash)
            </button>
            <button
              onClick={() => {
                setSelectedRole('forensic');
                setUseMapsGrounding(false);
              }}
              className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                selectedRole === 'forensic'
                  ? 'bg-purple-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
              title="Deep complex reasoning for APT & reverse-engineering (gemini-3.1-pro-preview)"
            >
              Deep Forensic (3.1 Pro)
            </button>
            <button
              onClick={() => {
                setSelectedRole('fast');
                setUseMapsGrounding(false);
              }}
              className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                selectedRole === 'fast'
                  ? 'bg-emerald-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
              title="Fast sub-second threat check (gemini-3.1-flash-lite)"
            >
              Fast Triage (Flash Lite)
            </button>
          </div>

          {/* Maps Grounding Toggle Button */}
          <button
            onClick={() => {
              const nextVal = !useMapsGrounding;
              setUseMapsGrounding(nextVal);
              if (nextVal) {
                setSelectedRole('general');
              }
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
              useMapsGrounding
                ? 'bg-emerald-600 text-white border-emerald-700 shadow-xs'
                : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
            }`}
            title="Ground answers with real-world Google Maps place & infrastructure data"
          >
            <MapPin className="w-3.5 h-3.5" />
            <span>Maps Grounding</span>
          </button>

          {/* Live Voice Assistant launcher */}
          {onOpenVoice && (
            <button
              onClick={onOpenVoice}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 transition-all shadow-2xs"
              title="Start real-time voice conversation with Live API"
            >
              <Mic className="w-3.5 h-3.5" />
              <span>Voice SOC</span>
            </button>
          )}

          {/* Clear history */}
          <button
            onClick={handleClearHistory}
            className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-200 transition-colors"
            title="Clear Chat History"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Model & Firebase Status Banner */}
      <div className="px-4 py-2 bg-slate-100/75 border-b border-slate-200 text-xs flex flex-wrap items-center justify-between gap-2 text-slate-600">
        <div className="flex items-center gap-2">
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span>
            Active Model: <strong className="text-slate-900 font-semibold">{currentModelInfo.name}</strong>
          </span>
          <span className="text-slate-400">•</span>
          <span>{currentModelInfo.badge}</span>
        </div>
        <div className="flex items-center gap-2">
          {user ? (
            <span className="flex items-center gap-1 text-emerald-700 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
              History Synced to Firestore ({user.email})
            </span>
          ) : (
            <span className="text-slate-500">Sign in with Google to persist chat history</span>
          )}
        </div>
      </div>

      {/* Scrollable Message Thread */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4 bg-slate-50/40">
        {messages.map((msg) => {
          const isUser = msg.role === 'user';
          return (
            <div
              key={msg.id}
              className={`flex gap-3 max-w-3xl ${isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'}`}
            >
              {/* Avatar Icon */}
              <div
                className={`h-8 w-8 rounded-full flex items-center justify-center shrink-0 text-white ${
                  isUser ? 'bg-blue-600' : 'bg-slate-800'
                }`}
              >
                {isUser ? (
                  user?.photoURL ? (
                    <img
                      src={user.photoURL}
                      alt="User"
                      className="h-8 w-8 rounded-full object-cover"
                      referrerPolicy="no-referrer"
                    />
                  ) : (
                    <UserIcon className="w-4 h-4" />
                  )
                ) : (
                  <Bot className="w-4 h-4" />
                )}
              </div>

              {/* Message Bubble */}
              <div className="flex flex-col space-y-1">
                <div className="flex items-center gap-2 text-[11px] text-slate-400 px-1">
                  <span className="font-semibold text-slate-600">
                    {isUser ? user?.displayName || 'SOC Analyst' : 'ThreatMail AI'}
                  </span>
                  {msg.model && (
                    <span className="text-[10px] bg-slate-200 text-slate-700 px-1.5 py-0.2 rounded font-mono">
                      {msg.model}
                    </span>
                  )}
                  <span>{msg.timestamp}</span>
                </div>

                <div
                  className={`p-3.5 rounded-2xl text-xs sm:text-sm leading-relaxed ${
                    isUser
                      ? 'bg-blue-600 text-white rounded-tr-xs shadow-xs'
                      : 'bg-white text-slate-800 border border-slate-200 rounded-tl-xs shadow-2xs'
                  }`}
                >
                  <div className="whitespace-pre-wrap">{msg.content}</div>

                  {/* Google Maps Grounding Links (Mandatory Requirement) */}
                  {msg.groundingLinks && msg.groundingLinks.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-200">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-900 mb-2">
                        <MapPin className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Google Maps Grounded Locations & Sources:</span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {msg.groundingLinks.map((link, idx) => (
                          <a
                            key={idx}
                            href={link.uri}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-start gap-2 p-2.5 rounded-lg bg-emerald-50/70 hover:bg-emerald-100/80 border border-emerald-200 text-emerald-950 transition-colors group"
                          >
                            <MapPin className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center justify-between gap-1">
                                <p className="font-semibold text-xs text-emerald-900 truncate group-hover:underline">
                                  {link.title || 'View on Google Maps'}
                                </p>
                                <ExternalLink className="w-3 h-3 text-emerald-600 shrink-0" />
                              </div>
                              {link.snippet && (
                                <p className="text-[11px] text-emerald-800 line-clamp-2 mt-0.5">
                                  {link.snippet}
                                </p>
                              )}
                            </div>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex gap-3 max-w-xl mr-auto">
            <div className="h-8 w-8 rounded-full bg-slate-800 text-white flex items-center justify-center shrink-0">
              <Bot className="w-4 h-4 animate-spin" />
            </div>
            <div className="p-3.5 rounded-2xl rounded-tl-xs bg-white border border-slate-200 text-slate-500 text-xs flex items-center gap-2 shadow-2xs">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" />
              <span>Analyzing threat intelligence with {currentModelInfo.name}...</span>
            </div>
          </div>
        )}

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Quick Prompt Chips */}
      <div className="px-4 py-2 border-t border-slate-200 bg-white flex items-center gap-2 overflow-x-auto text-xs scrollbar-none">
        <span className="text-slate-400 font-semibold uppercase tracking-wider text-[10px] shrink-0">
          Suggested:
        </span>
        {samplePrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(p.text)}
            disabled={isLoading}
            className="px-2.5 py-1 rounded-full bg-slate-100 hover:bg-slate-200 text-slate-700 whitespace-nowrap transition-colors shrink-0 disabled:opacity-50"
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Message Input Bar */}
      <div className="p-3 sm:p-4 border-t border-slate-200 bg-white">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder={`Ask ${currentModelInfo.name} about email headers, malware IOCs, phishing tactics...`}
            disabled={isLoading}
            className="flex-1 bg-slate-50 border border-slate-300 focus:border-blue-500 focus:bg-white focus:outline-none px-3.5 py-2.5 rounded-xl text-xs sm:text-sm text-slate-900 placeholder:text-slate-400 shadow-2xs transition-colors"
          />
          <button
            type="submit"
            disabled={!inputMessage.trim() || isLoading}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium text-xs sm:text-sm px-4 py-2.5 rounded-xl shadow-xs transition-colors shrink-0"
          >
            <Send className="w-4 h-4" />
            <span className="hidden sm:inline">Send</span>
          </button>
        </form>
      </div>
    </div>
  );
};
