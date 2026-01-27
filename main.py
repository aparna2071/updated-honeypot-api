from dotenv import load_dotenv
load_dotenv()

import os
import json
import requests
from fastapi import FastAPI, HTTPException, Header, Body
from pydantic import BaseModel
from typing import List, Optional
from google import genai
from datetime import datetime

# Initialize FastAPI and Gemini
app = FastAPI()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# --- Configuration ---
GUVI_EVAL_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SECRET_API_KEY = os.getenv("X_API_KEY", "your-secure-key")

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
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

# --- Gemini Logic ---
def get_gemini_json(prompt: str, schema: dict):
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={"response_mime_type": "application/json", "response_schema": schema}
    )
    return json.loads(response.text)

def get_gemini_text(prompt: str):
    response = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
    return response.text

# --- API Endpoints ---
@app.post("/honeypot")
async def honeypot_handler(data: HoneypotRequest, x_api_key: str = Header(None)):
    if x_api_key != SECRET_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    history_str = "\n".join([f"{m.sender}: {m.text}" for m in data.conversationHistory])
    
    # STEP 1: SCAM DETECTION & LANGUAGE ANALYSIS
    detect_schema = {
        "type": "OBJECT",
        "properties": {
            "scamDetected": {"type": "BOOLEAN"},
            "reason": {"type": "STRING"},
            "scamType": {"type": "STRING"},
            "language": {"type": "STRING"}
        },
        "required": ["scamDetected", "language"]
    }
    detection = get_gemini_json(f"Detect scam and language in: {data.message.text}\nHistory: {history_str}", detect_schema)
    
    scam_detected = detection.get("scamDetected", False)
    detected_lang = detection.get("language", "English")
    
    if not scam_detected:
        return {"status": "success", "scamDetected": False, "agentReply": "What is this?"}

    # STEP 2: ENGAGEMENT (SHORT & LANGUAGE MIRRORED)
    engage_prompt = f"Act as a naive victim. REPLY IN {detected_lang}. KEEP IT SHORT (max 12 words). Latest: {data.message.text}"
    agent_reply = get_gemini_text(engage_prompt)
    
    # STEP 3: INTELLIGENCE EXTRACTION
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
    intelligence = get_gemini_json(f"Extract intel from: {history_str}\n{data.message.text}", extract_schema)

    # STEP 4: MANDATORY GUVI CALLBACK
    try:
        payload = {
            "sessionId": data.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": len(data.conversationHistory) + 2,
            "extractedIntelligence": intelligence,
            "agentNotes": f"Detected {detection.get('scamType', 'scam')} in {detected_lang}"
        }
        requests.post(GUVI_EVAL_URL, json=payload, timeout=5)
    except Exception:
        pass

    return {
        "status": "success",
        "scamDetected": True,
        "language": detected_lang,
        "agentReply": agent_reply,
        "extractedIntelligence": intelligence
    }
  