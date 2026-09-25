import React, { useState, useEffect, useRef } from 'react';
import {
  Mic,
  MicOff,
  PhoneOff,
  Volume2,
  VolumeX,
  Sparkles,
  Radio,
  AlertCircle,
  X,
  RotateCcw,
  CheckCircle2,
} from 'lucide-react';

interface LiveVoiceModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface TranscriptLine {
  id: string;
  sender: 'user' | 'model';
  text: string;
  timestamp: string;
}

export const LiveVoiceModal: React.FC<LiveVoiceModalProps> = ({ isOpen, onClose }) => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isConnecting, setIsConnecting] = useState<boolean>(false);
  const [isMuted, setIsMuted] = useState<boolean>(false);
  const [statusText, setStatusText] = useState<string>('Ready to start');
  const [error, setError] = useState<string | null>(null);
  const [isSpeaking, setIsSpeaking] = useState<boolean>(false);
  const [isAiResponding, setIsAiResponding] = useState<boolean>(false);

  // Live Transcripts
  const [transcripts, setTranscripts] = useState<TranscriptLine[]>([]);

  // Refs for Web Audio API & WebSocket
  const wsRef = useRef<WebSocket | null>(null);
  const inputAudioCtxRef = useRef<AudioContext | null>(null);
  const outputAudioCtxRef = useRef<AudioContext | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const scriptProcessorRef = useRef<ScriptProcessorNode | null>(null);
  const nextStartTimeRef = useRef<number>(0);
  const activeSourcesRef = useRef<AudioBufferSourceNode[]>([]);
  const isMutedRef = useRef<boolean>(false);
  const transcriptEndRef = useRef<HTMLDivElement | null>(null);

  isMutedRef.current = isMuted;

  // Auto-scroll transcripts
  useEffect(() => {
    transcriptEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [transcripts]);

  // Clean up when modal closes
  useEffect(() => {
    if (!isOpen) {
      handleStopSession();
    }
  }, [isOpen]);

  // Float32 to 16-bit PCM little-endian Base64 encoder
  const floatTo16BitPcmBase64 = (input: Float32Array): string => {
    const buffer = new ArrayBuffer(input.length * 2);
    const view = new DataView(buffer);
    for (let i = 0; i < input.length; i++) {
      let s = Math.max(-1, Math.min(1, input[i]));
      view.setInt16(i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    }
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  // Playback 24kHz PCM Audio Chunk gaplessly
  const playAudioChunk = (base64Pcm: string) => {
    if (!outputAudioCtxRef.current) return;
    const ctx = outputAudioCtxRef.current;
    if (ctx.state === 'suspended') {
      ctx.resume();
    }

    try {
      const binaryString = atob(base64Pcm);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const int16 = new Int16Array(bytes.buffer);
      const float32 = new Float32Array(int16.length);
      for (let i = 0; i < int16.length; i++) {
        float32[i] = int16[i] / 32768.0;
      }

      const audioBuffer = ctx.createBuffer(1, float32.length, 24000);
      audioBuffer.copyToChannel(float32, 0);

      const sourceNode = ctx.createBufferSource();
      sourceNode.buffer = audioBuffer;
      sourceNode.connect(ctx.destination);

      const currentTime = ctx.currentTime;
      const startTime = Math.max(currentTime, nextStartTimeRef.current);
      sourceNode.start(startTime);
      nextStartTimeRef.current = startTime + audioBuffer.duration;

      activeSourcesRef.current.push(sourceNode);
      sourceNode.onended = () => {
        activeSourcesRef.current = activeSourcesRef.current.filter((s) => s !== sourceNode);
        if (activeSourcesRef.current.length === 0) {
          setIsAiResponding(false);
        }
      };

      setIsAiResponding(true);
    } catch (e) {
      console.warn('Error playing audio chunk:', e);
    }
  };

  // Stop queued audio on interruption
  const stopAllAudio = () => {
    activeSourcesRef.current.forEach((src) => {
      try {
        src.stop();
      } catch (e) {}
    });
    activeSourcesRef.current = [];
    if (outputAudioCtxRef.current) {
      nextStartTimeRef.current = outputAudioCtxRef.current.currentTime;
    }
    setIsAiResponding(false);
  };

  const handleStartSession = async () => {
    setError(null);
    setIsConnecting(true);
    setStatusText('Connecting to Gemini Live API...');

    try {
      // 1. Initialize AudioContexts
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      inputAudioCtxRef.current = new AudioCtx({ sampleRate: 16000 });
      outputAudioCtxRef.current = new AudioCtx({ sampleRate: 24000 });

      if (inputAudioCtxRef.current.state === 'suspended') {
        await inputAudioCtxRef.current.resume();
      }
      if (outputAudioCtxRef.current.state === 'suspended') {
        await outputAudioCtxRef.current.resume();
      }
      nextStartTimeRef.current = outputAudioCtxRef.current.currentTime;

      // 2. Request microphone stream
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: 1,
          sampleRate: 16000,
          echoCancellation: true,
          noiseSuppression: true,
        },
      });
      mediaStreamRef.current = stream;

      // 3. Connect to WebSocket
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/live`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('Connected to Live Voice WebSocket');
        setIsConnected(true);
        setIsConnecting(false);
        setStatusText('Live Audio Connected • Speak freely');

        // Setup microphone processor
        if (!inputAudioCtxRef.current) return;
        const source = inputAudioCtxRef.current.createMediaStreamSource(stream);
        const processor = inputAudioCtxRef.current.createScriptProcessor(4096, 1, 1);
        scriptProcessorRef.current = processor;

        source.connect(processor);
        processor.connect(inputAudioCtxRef.current.destination);

        processor.onaudioprocess = (e) => {
          if (isMutedRef.current || ws.readyState !== WebSocket.OPEN) {
            setIsSpeaking(false);
            return;
          }

          const channelData = e.inputBuffer.getChannelData(0);

          // Detect volume level for speech pulse
          let sum = 0;
          for (let i = 0; i < channelData.length; i++) {
            sum += Math.abs(channelData[i]);
          }
          const avg = sum / channelData.length;
          setIsSpeaking(avg > 0.02);

          const base64Audio = floatTo16BitPcmBase64(channelData);
          ws.send(JSON.stringify({ audio: base64Audio }));
        };
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'audio' && msg.audio) {
            playAudioChunk(msg.audio);
          } else if (msg.type === 'interrupted') {
            stopAllAudio();
          } else if (msg.type === 'transcript' && msg.text) {
            setTranscripts((prev) => {
              const last = prev[prev.length - 1];
              if (last && last.sender === msg.sender) {
                return [
                  ...prev.slice(0, -1),
                  { ...last, text: last.text + ' ' + msg.text },
                ];
              } else {
                return [
                  ...prev,
                  {
                    id: `line-${Date.now()}`,
                    sender: msg.sender,
                    text: msg.text,
                    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                  },
                ];
              }
            });
          } else if (msg.type === 'status' && msg.status === 'ready') {
            setStatusText('Gemini Live listening...');
          } else if (msg.type === 'error') {
            setError(msg.error || 'Live voice session reported an error');
          }
        } catch (e) {
          console.warn('Failed to parse WS live message:', e);
        }
      };

      ws.onerror = (e) => {
        console.error('WebSocket live error:', e);
        setError('Live API connection interrupted. Please ensure backend is running.');
        setIsConnecting(false);
      };

      ws.onclose = () => {
        console.log('WebSocket live closed');
        setIsConnected(false);
        setIsConnecting(false);
        setStatusText('Session ended');
      };
    } catch (err: any) {
      console.error('Error starting live session:', err);
      setError(err?.message || 'Could not access microphone or connect to Live API.');
      setIsConnecting(false);
      setIsConnected(false);
    }
  };

  const handleStopSession = () => {
    stopAllAudio();

    if (scriptProcessorRef.current) {
      try {
        scriptProcessorRef.current.disconnect();
      } catch (e) {}
      scriptProcessorRef.current = null;
    }

    if (mediaStreamRef.current) {
      mediaStreamRef.current.getTracks().forEach((t) => t.stop());
      mediaStreamRef.current = null;
    }

    if (inputAudioCtxRef.current) {
      try {
        inputAudioCtxRef.current.close();
      } catch (e) {}
      inputAudioCtxRef.current = null;
    }

    if (outputAudioCtxRef.current) {
      try {
        outputAudioCtxRef.current.close();
      } catch (e) {}
      outputAudioCtxRef.current = null;
    }

    if (wsRef.current) {
      try {
        wsRef.current.close();
      } catch (e) {}
      wsRef.current = null;
    }

    setIsConnected(false);
    setIsConnecting(false);
    setIsSpeaking(false);
    setIsAiResponding(false);
    setStatusText('Session ended');
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-rose-500 to-amber-500 text-white flex items-center justify-center shadow-xs">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900">Live Voice SOC Incident Response</h3>
                <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200">
                  gemini-3.1-flash-live-preview
                </span>
              </div>
              <p className="text-xs text-slate-500">
                Real-time spoken dialogue with bidirectional 16kHz/24kHz streaming audio
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Visual Pulse & Interactive Canvas */}
        <div className="p-8 flex flex-col items-center justify-center bg-radial from-slate-50 to-white border-b border-slate-200">
          {/* Audio Visualizer Circle */}
          <div className="relative flex items-center justify-center">
            {/* Animated Pulses */}
            {isConnected && (isSpeaking || isAiResponding) && (
              <>
                <span className={`absolute inline-flex h-36 w-36 rounded-full opacity-30 animate-ping ${
                  isAiResponding ? 'bg-blue-400' : 'bg-emerald-400'
                }`} />
                <span className={`absolute inline-flex h-28 w-28 rounded-full opacity-40 animate-pulse ${
                  isAiResponding ? 'bg-blue-500' : 'bg-emerald-500'
                }`} />
              </>
            )}

            {/* Core Mic Button */}
            <div
              className={`h-24 w-24 rounded-full flex items-center justify-center text-white transition-all shadow-lg ${
                isConnected
                  ? isAiResponding
                    ? 'bg-blue-600 ring-4 ring-blue-100'
                    : isSpeaking
                    ? 'bg-emerald-600 ring-4 ring-emerald-100'
                    : 'bg-slate-800'
                  : 'bg-slate-400'
              }`}
            >
              {isConnected ? (
                isAiResponding ? (
                  <Volume2 className="w-10 h-10 animate-bounce" />
                ) : isMuted ? (
                  <MicOff className="w-10 h-10 text-red-200" />
                ) : (
                  <Mic className="w-10 h-10" />
                )
              ) : (
                <Radio className="w-10 h-10 opacity-70" />
              )}
            </div>
          </div>

          {/* Status Text & State */}
          <div className="mt-6 text-center">
            <div className="flex items-center justify-center gap-2 mb-1">
              <span className={`h-2.5 w-2.5 rounded-full ${
                isConnected ? (isAiResponding ? 'bg-blue-500 animate-pulse' : 'bg-emerald-500') : 'bg-slate-400'
              }`} />
              <p className="text-sm font-semibold text-slate-800">
                {isConnected
                  ? isAiResponding
                    ? 'Gemini Voice Assistant Speaking...'
                    : isSpeaking
                    ? 'Listening to Analyst...'
                    : isMuted
                    ? 'Microphone Muted'
                    : 'Listening for Incident Commands...'
                  : statusText}
              </p>
            </div>
            <p className="text-xs text-slate-500 max-w-sm">
              {isConnected
                ? 'Speak naturally about suspicious emails, attacker domains, or mitigation steps.'
                : 'Click "Start Conversation" to begin live audio streaming with Gemini.'}
            </p>
          </div>

          {/* Controls Bar */}
          <div className="mt-6 flex items-center gap-3">
            {!isConnected ? (
              <button
                onClick={handleStartSession}
                disabled={isConnecting}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold px-6 py-2.5 rounded-xl shadow-xs transition-colors"
              >
                <Radio className="w-4 h-4" />
                <span>{isConnecting ? 'Connecting...' : 'Start Conversation'}</span>
              </button>
            ) : (
              <>
                <button
                  onClick={() => setIsMuted(!isMuted)}
                  className={`flex items-center gap-1.5 text-xs font-medium px-4 py-2.5 rounded-xl border transition-colors ${
                    isMuted
                      ? 'bg-amber-50 text-amber-700 border-amber-300'
                      : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  {isMuted ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
                  <span>{isMuted ? 'Unmute Mic' : 'Mute Mic'}</span>
                </button>
                <button
                  onClick={handleStopSession}
                  className="flex items-center gap-1.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold px-5 py-2.5 rounded-xl shadow-xs transition-colors"
                >
                  <PhoneOff className="w-4 h-4" />
                  <span>End Session</span>
                </button>
              </>
            )}
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Live Transcripts Section */}
        <div className="flex-1 overflow-y-auto p-4 max-h-56 bg-slate-50/50">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Live Real-Time Transcripts
            </span>
            {transcripts.length > 0 && (
              <button
                onClick={() => setTranscripts([])}
                className="text-[11px] text-slate-400 hover:text-slate-600 underline"
              >
                Clear
              </button>
            )}
          </div>

          {transcripts.length === 0 ? (
            <div className="text-center py-6 text-xs text-slate-400 italic">
              Spoken conversation transcripts will stream here in real time...
            </div>
          ) : (
            <div className="space-y-2.5">
              {transcripts.map((line) => (
                <div
                  key={line.id}
                  className={`flex flex-col text-xs p-2.5 rounded-xl ${
                    line.sender === 'user'
                      ? 'bg-blue-50 text-blue-900 border border-blue-100 ml-8'
                      : 'bg-white text-slate-800 border border-slate-200 mr-8 shadow-2xs'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] text-slate-400 mb-0.5">
                    <span className="font-semibold text-slate-600">
                      {line.sender === 'user' ? 'You' : 'Gemini Voice SOC'}
                    </span>
                    <span>{line.timestamp}</span>
                  </div>
                  <p>{line.text}</p>
                </div>
              ))}
              <div ref={transcriptEndRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
