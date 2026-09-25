import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';
import { Modality, LiveServerMessage } from '@google/genai';
import { getAi } from './geminiService.js';

export function setupLiveVoiceWebSocket(server: http.Server) {
  const wss = new WebSocketServer({
    server,
    path: '/api/live',
  });

  console.log('Live Voice WebSocket Server registered at /api/live');

  wss.on('connection', async (clientWs: WebSocket) => {
    console.log('Client connected to Live Voice WebSocket');
    let session: any = null;
    let isClosed = false;

    try {
      const ai = getAi();
      session = await ai.live.connect({
        model: 'gemini-3.1-flash-live-preview',
        config: {
          responseModalities: [Modality.AUDIO],
          speechConfig: {
            voiceConfig: { prebuiltVoiceConfig: { voiceName: 'Zephyr' } },
          },
          systemInstruction: `You are ThreatMail AI's real-time Security Operations Center (SOC) Voice Assistant.
You converse with cybersecurity analysts about live threats, phishing investigations, email forensics, and emergency containment actions.
Keep spoken responses conversational, concise, and clear. Avoid reading long URLs or hashes aloud unless requested.`,
          outputAudioTranscription: {},
          inputAudioTranscription: {},
        },
        callbacks: {
          onmessage: (message: LiveServerMessage) => {
            if (isClosed || clientWs.readyState !== WebSocket.OPEN) return;

            // 1. Audio data
            const audioData = message.serverContent?.modelTurn?.parts?.[0]?.inlineData?.data;
            if (audioData) {
              clientWs.send(JSON.stringify({ type: 'audio', audio: audioData }));
            }

            // 2. Interruption event
            if (message.serverContent?.interrupted) {
              clientWs.send(JSON.stringify({ type: 'interrupted' }));
            }

            // 3. Output Transcription
            const parts = message.serverContent?.modelTurn?.parts;
            if (parts) {
              for (const part of parts) {
                if (part.text) {
                  clientWs.send(JSON.stringify({ type: 'transcript', text: part.text, sender: 'model' }));
                }
              }
            }
          },
          onclose: () => {
            console.log('Gemini Live session closed');
            if (!isClosed && clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({ type: 'status', status: 'closed' }));
            }
          },
          onerror: (err: any) => {
            console.error('Gemini Live session error:', err);
            if (!isClosed && clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({ type: 'error', error: err?.message || 'Live voice session error' }));
            }
          },
        },
      });

      // Send initial ready signal to client
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(JSON.stringify({ type: 'status', status: 'ready' }));
      }

      clientWs.on('message', (rawData: any) => {
        if (!session) return;
        try {
          const parsed = JSON.parse(rawData.toString());
          if (parsed.audio) {
            // Send 16kHz PCM audio
            session.sendRealtimeInput({
              audio: { data: parsed.audio, mimeType: 'audio/pcm;rate=16000' },
            });
          } else if (parsed.text) {
            // Send text input
            session.sendRealtimeInput({
              text: parsed.text,
            });
          }
        } catch (e: any) {
          console.error('Error handling message from client WS:', e);
        }
      });

      clientWs.on('close', () => {
        isClosed = true;
        try {
          if (session) {
            session.close();
          }
        } catch (e) {
          // ignore cleanup errors
        }
      });

      clientWs.on('error', (err) => {
        console.error('Client WS error:', err);
        isClosed = true;
        try {
          if (session) {
            session.close();
          }
        } catch (e) {}
      });
    } catch (err: any) {
      console.error('Failed to initialize Gemini Live connection:', err);
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(JSON.stringify({
          type: 'error',
          error: `Live API error: ${err?.message || 'Unable to connect to gemini-3.1-flash-live-preview'}`,
        }));
      }
    }
  });
}
