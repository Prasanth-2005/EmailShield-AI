import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
dotenv.config();

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY!,
  httpOptions: { headers: { 'User-Agent': 'aistudio-build' } },
});

const models = [
  'gemini-3.6-flash',
  'gemini-2.0-flash',
  'gemini-2.0-flash-001',
  'gemini-2.5-flash',
  'gemini-2.5-flash-lite',
  'gemini-flash-lite-latest',
  'gemini-flash-latest',
];

for (const model of models) {
  try {
    const r = await ai.models.generateContent({
      model,
      contents: 'Reply with the single word OK.',
      config: { responseMimeType: 'text/plain' },
    });
    console.log(`${model.padEnd(26)} -> OK  "${(r.text || '').trim().slice(0, 20)}"  tokens=${r.usageMetadata?.totalTokenCount}`);
  } catch (e: any) {
    const msg = (e?.message || String(e)).replace(/\s+/g, ' ').slice(0, 140);
    console.log(`${model.padEnd(26)} -> ${e?.status || 'ERR'}  ${msg}`);
  }
}
