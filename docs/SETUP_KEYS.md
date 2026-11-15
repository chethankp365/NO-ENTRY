# NO ENTRY — API Keys, Voice, AI Orchestration & Optional Cloud Database Setup

This guide explains how to configure optional external AI, voice, intent-classification, and PostgreSQL integrations for **GHOST** in **NO ENTRY**.

> **Important Security Rules**
> - Store all real keys **only** in `backend/.env` (or root `.env`).
> - Never commit `.env` or `backend/.env` to Git (both are ignored in `.gitignore`).
> - Never paste keys into frontend HTML/JS or share them in chat.
> - **NO ENTRY runs 100% offline with zero keys**: when no keys are configured, Ghost automatically runs in deterministic scripted mode (`Ghost offline: scripted hints`).
> - **No manual model maintenance**: each provider integration automatically uses its available/default chat, voice, or router configuration based solely on the API key you provide.

---

## 1. Create `backend/.env` and Generate `SECRET_KEY`

Copy `backend/.env.example` (or `.env.example`) to `backend/.env`:

```bash
cp backend/.env.example backend/.env
```

Generate a cryptographically random `SECRET_KEY` for JWT session signing:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the generated hex string into `backend/.env`:

```env
SECRET_KEY=<your-generated-64-char-hex-string>
```

---

## 2. Obtaining Optional Provider API Keys

Configure any combination of the providers below. You only need the API key variable for each provider you want enabled.

### A. Groq (Primary LLM When Configured)
1. Open [Groq Console](https://console.groq.com/keys) and sign in.
2. Click **Create API Key**, name it `no-entry-ghost`, and copy the key (`gsk_...`).
3. Set in `backend/.env`:
   ```env
   GROQ_API_KEY=gsk_...
   ```
   The Groq adapter queries your account's active chat models automatically at runtime.

### B. Google Gemini (`google-genai` SDK)
1. Open [Google AI Studio](https://aistudio.google.com/apikey) and sign in with a Google account.
2. Click **Create API key** and copy the generated key.
3. Set in `backend/.env`:
   ```env
   GEMINI_API_KEY=...
   ```
   The Gemini adapter queries `generateContent`-capable models from your key automatically at runtime.

### C. OpenRouter (Fallback LLM)
1. Open [OpenRouter Keys](https://openrouter.ai/settings/keys) and create a key (`sk-or-v1-...`).
2. Set in `backend/.env`:
   ```env
   OPENROUTER_API_KEY=sk-or-v1-...
   ```
   The OpenRouter adapter routes requests through OpenRouter's automatic routing configuration.

### D. Deepgram (Voice STT & TTS)
1. Open [Deepgram Console](https://console.deepgram.com/) and create a project API key.
2. Set in `backend/.env`:
   ```env
   DEEPGRAM_API_KEY=...
   ```
   Both speech-to-text (`/v1/listen`) and text-to-speech (`/v1/speak`) use Deepgram's built-in defaults. Audio clips stay in memory only and are never saved to disk.

### E. Optional Hugging Face Token (Zero-Shot Intent Classification)
1. Open [Hugging Face Access Tokens](https://huggingface.co/settings/tokens).
2. Create a token (`hf_...`) with **Make calls to Inference Providers** / **Read** permission.
3. Set in `backend/.env`:
   ```env
   HF_TOKEN=hf_...
   ```
   If omitted, exhausted (HTTP 402), or rate-limited, Ghost transparently uses fast local keyword routing and always respects your selected quick-action button.

---

## 3. Configuring Provider Priority & Timeouts

Change provider routing order in `backend/.env` without modifying Python code:

```env
# Default priority
AI_PROVIDER_PRIORITY="groq,gemini,openrouter"

# Example: prefer Gemini first
# AI_PROVIDER_PRIORITY="gemini,groq,openrouter"

AI_REQUEST_TIMEOUT_SEC=20
AI_MAX_RETRIES=1
```

---

## 4. Configuring Optional PostgreSQL (`DATABASE_URL`)

SQLite (`sqlite:///./data/no_entry.db`) is enabled by default with zero setup.  
To use PostgreSQL (`psycopg` v3 is included in `requirements.txt`):

```env
DATABASE_URL="postgresql://username:password@host:5432/no_entry"
```

The backend automatically normalizes `postgres://` and `postgresql://` URLs to `postgresql+psycopg://` with connection health checks (`pool_pre_ping=True`). Startup tables (`User`, `MissionProgress`, `Badge`, `Report`, `EventLog`, `GhostRateLimit`) are created automatically via SQLModel.

---

## 5. Local Inference (TensorFlow Lite Status)

No `.tflite` model artifact exists in the repository; therefore optional local TensorFlow Lite inference is **not configured** (`local_inference.tflite_configured = false` in `GET /api/ghost/status`). Ghost requires no external ML runtime downloads.

---

## 6. Testing Integrations Individually & Verifying Fallback

1. **Check Safe Provider Status (Never Prints Secrets):**
   ```bash
   curl http://127.0.0.1:8000/api/ghost/status
   ```
   Verify `"configured": true` appears only for providers whose keys you added.

2. **Test One Provider at a Time:**
   - Leave only `GROQ_API_KEY` set (clear `GEMINI_API_KEY` and `OPENROUTER_API_KEY` or set `AI_PROVIDER_PRIORITY="groq"`), restart Uvicorn, open Ghost on `/command-center`, and ask a question. The badge should show `GHOST // GROQ`.
   - Repeat isolating `gemini` (`GHOST // GEMINI`) and `openrouter` (`GHOST // OPENROUTER`).

3. **Test Automatic Failover:**
   - Set an invalid dummy value in `GROQ_API_KEY` alongside a valid `GEMINI_API_KEY` and default priority `groq,gemini,openrouter`.
   - Ask Ghost a question: Groq fails, orchestrator automatically fails over to Gemini without dropping the request.

4. **Test Scripted Offline Mode:**
   - Leave all three LLM keys empty (`GROQ_API_KEY=`, `GEMINI_API_KEY=`, `OPENROUTER_API_KEY=`).
   - Ghost displays `Ghost offline: scripted hints` and serves mission-YAML hints, log analysis, and rule reviews locally.

5. **Test Deepgram Voice Input & Output:**
   - Open the Ghost drawer -> click **MIC**, grant browser microphone access, speak a question, and click **STOP**. Recognized speech populates the input box and sends to Ghost.
   - Click **VOICE: OFF** to switch to **VOICE: ON** (or click **SPEAK** on a reply) to play synthesized speech. Disabling voice keeps replies silent and text-only.

---

## 7. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Status shows `Ghost offline: scripted hints` even with a key set | Server started before editing `backend/.env`, or wrong variable name | Restart Uvicorn and verify exact env var names in `backend/.env`. |
| Provider HTTP 401 / 403 | Invalid/revoked key or unverified OpenRouter account | Regenerate key in provider console and update `backend/.env`. |
| HTTP 402 from Hugging Face | Free monthly serverless inference quota depleted | Expected safe degradation: Ghost keeps running via local intent routing. |
| HTTP 429 or `[RATE LIMIT 20/20/hr]` | Exceeded Ghost chat limit (`20`/hr) or upstream quota | Scripted mission hints continue working automatically until the 1-hour window resets. |
| `MIC: PERMISSION DENIED` | Browser blocked mic access | Allow microphone permissions in browser site settings or type questions manually. |
| `TTS: TEXT-ONLY FALLBACK` | `DEEPGRAM_API_KEY` missing or Deepgram quota error | Text streaming stays active; configure valid `DEEPGRAM_API_KEY` when ready. |
