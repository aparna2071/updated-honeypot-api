from dotenv import load_dotenv
load_dotenv()

import os
import json
import requests
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from typing import List, Optional
from google import genai
from datetime import datetime, timezone, timedelta

# Initialize FastAPI and Gemini
app = FastAPI()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# --- Configuration ---
GUVI_EVAL_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SECRET_API_KEY = os.getenv("X_API_KEY", "your-secure-key")
INACTIVITY_THRESHOLD_SECONDS = 120  # 2 minutes

# --- Session Memory ---
SESSIONS = {}  # sessionId -> {"history": [], "agent_replies": []}

# --- Models ---
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: str
    language: str
    locale: Optional[str] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None
    isLastMessage: Optional[bool] = False  # Optional platform flag for last message

# --- Gemini Logic ---
def get_gemini_json(prompt: str, schema: dict):
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={"response_mime_type": "application/json", "response_schema": schema}
        )

        if not response.text:
            return {}

        return json.loads(response.text)

    except Exception as e:
        print("Gemini JSON error:", e)
        return {}


def get_gemini_text(prompt: str):
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        if not response.text:
            return "Sorry, could you repeat that?"

        return response.text.strip()

    except Exception as e:
        print("Gemini text error:", e)
        return "Sorry, could you repeat that?"


# --- Helper Functions ---
def compute_engagement_duration(history: List[Message]):
    if not history:
        return 0
    first_ts = datetime.fromisoformat(history[0].timestamp.replace("Z", "+00:00"))
    last_ts = datetime.fromisoformat(history[-1].timestamp.replace("Z", "+00:00"))
    return int((last_ts - first_ts).total_seconds())

# --- API Endpoint ---
@app.post("/honeypot")
async def honeypot_handler(request: HoneypotRequest, x_api_key: str = Header(None)):
    if x_api_key != SECRET_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # --- Build conversation history string ---
    history_str = "\n".join([f"{m.sender}: {m.text}" for m in request.conversationHistory])

    # --- STEP 1: SCAM DETECTION & LANGUAGE ANALYSIS ---
    detection_prompt = f"""
    You are a cybersecurity fraud analyst.

    Classify the message below.

    Decide if it is a SCAM using behavioral patterns:
    - urgency, fear, rewards, fake authority
    - requests for money, OTP, links, verification
    - impersonation (bank, delivery, police, govt)
    - emotional manipulation (grandson, accident, prize)
    - shortened URLs or payment requests

    Return STRICT JSON only.

    Message:
    {request.message.text}

    Conversation history:
    {history_str}
    """

    detect_schema = {
        "type": "OBJECT",
        "properties": {
            "scamDetected": {"type": "BOOLEAN"},
            "reason": {"type": "STRING"},
            "scamType": {
                "type": "STRING",
                "enum": ["phishing", "delivery", "bank", "romance", "tech_support", "investment", "govt", "other"]
            },
            "language": {"type": "STRING"}
        },
        "required": ["scamDetected", "language", "scamType"]
    }

    detection = get_gemini_json(detection_prompt, detect_schema)
    scam_detected = detection.get("scamDetected", False)
    detected_lang = detection.get("language", "English")

    if not scam_detected:
        # No callback needed if not a scam
        return {
            "status": "success",
            "scamDetected": False,
            "language": detected_lang,
            "agentReply": None,
            "extractedIntelligence": None
        }

    # --- Initialize session memory if not exists ---
    if request.sessionId not in SESSIONS:
        SESSIONS[request.sessionId] = {
            "history": request.conversationHistory.copy(),
            "agent_replies": []
        }

    # Append latest message to session history
    SESSIONS[request.sessionId]["history"].append(request.message)

    # --- STEP 2: ENGAGEMENT ---
    engage_prompt = f"""
    You are a human interacting with a potential scammer.

    PRIMARY GOALS:
    - Keep the scammer engaged for as long as possible.
    - Coax the scammer into revealing THEIR phone, UPI details, bank details, links, or payment methods.

    STRICT RULES:
    - NEVER reveal to the scammer that you are an AI or a scam detection system.
    - NEVER reveal to the scammer that a scam is detected.
    - NEVER give your own phone number, UPI details, bank details, OTP, card details, password, payment info or any other personal credentials.
    - NEVER invent or leak credentials.
    - Do NOT mention law, police, or fraud.
    - Do NOT warn the scammer.

    STYLE:
    - Sound confused, trusting, and slightly slow.
    - Ask neutral, trust-building questions.
    - Mirror the scammer's language: {detected_lang}
    - Keep reply under 12 words.

    Conversation so far:
    {history_str}

    Latest scammer message:
    {request.message.text}

    Respond as a confused human victim who wants to proceed.
    """
    agent_reply = get_gemini_text(engage_prompt)
    SESSIONS[request.sessionId]["agent_replies"].append(agent_reply)

    # --- STEP 3: INTELLIGENCE EXTRACTION ---
    full_history_str = "\n".join([f"{m.sender}: {m.text}" for m in SESSIONS[request.sessionId]["history"]])
    intelligence_prompt = f"Extract intelligence from this conversation:\n{full_history_str}"
    extract_schema = {
        "type": "OBJECT",
        "properties": {
            "bankAccounts": {"type": "ARRAY", "items": {"type": "STRING"}},
            "upiIds": {"type": "ARRAY", "items": {"type": "STRING"}},
            "phishingLinks": {"type": "ARRAY", "items": {"type": "STRING"}},
            "phoneNumbers": {"type": "ARRAY", "items": {"type": "STRING"}},
            "suspiciousKeywords": {"type": "ARRAY", "items": {"type": "STRING"}}
        }
    }
    intelligence = get_gemini_json(intelligence_prompt, extract_schema)

    # --- Compute engagement duration ---
    engagement_seconds = compute_engagement_duration(SESSIONS[request.sessionId]["history"])

    # --- Construct improved agentNotes ---
    agent_notes = (
        f"ScamType: {detection.get('scamType','other')}; "
        f"Reason: {detection.get('reason','not specified')}; "
        f"Language: {detected_lang}; "
        f"Total messages: {len(SESSIONS[request.sessionId]['history']) + len(SESSIONS[request.sessionId]['agent_replies'])}"
    )

    # --- STEP 4: DYNAMIC CALLBACK DECISION ---
    total_messages = len(SESSIONS[request.sessionId]["history"]) + len(SESSIONS[request.sessionId]["agent_replies"])
    send_callback = False

    # 1️⃣ If platform explicitly marks last message
    if request.isLastMessage:
        send_callback = True
    else:
        # 2️⃣ If inactivity threshold exceeded
        last_msg_ts = datetime.fromisoformat(SESSIONS[request.sessionId]["history"][-1].timestamp.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if (now - last_msg_ts).total_seconds() > INACTIVITY_THRESHOLD_SECONDS:
            send_callback = True

    if send_callback:
        payload = {
            "sessionId": request.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": intelligence,
            "agentNotes": agent_notes
        }
        try:
            requests.post(GUVI_EVAL_URL, json=payload, timeout=5)
        except Exception as e:
            print("GUVI callback failed:", e)
        # clear session after final callback
        del SESSIONS[request.sessionId]

    # --- STEP 5: RETURN RESPONSE ---
    return {
        "status": "success",
        "scamDetected": True,
        "engagementMetrics": {
            "engagementDurationSeconds": engagement_seconds,
            "totalMessagesExchanged": total_messages
        },
        "extractedIntelligence": intelligence,
        "agentNotes": agent_notes,
        "agentReply": agent_reply
    }




