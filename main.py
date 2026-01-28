import os
import json
import requests
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
from google import genai

app = FastAPI()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

GUVI_EVAL_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SECRET_API_KEY = os.getenv("X_API_KEY", "your-secure-key")

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []

def guvi_callback(payload: dict):
    try: requests.post(GUVI_EVAL_URL, json=payload, timeout=5)
    except: pass

@app.post("/honeypot")
async def handle(data: HoneypotRequest, bg: BackgroundTasks, auth: str = Header(None)):
    if auth != SECRET_API_KEY: raise HTTPException(status_code=401)
    
    # SINGLE-PASS OPTIMIZATION (<10s Latency)
    ctx = "\n".join([f"{m.sender}: {m.text}" for m in data.conversationHistory[-5:]])
    prompt = f"SYSTEM: Analyze interaction.\nCTX: {ctx}\nNEW: {data.message.text}"
    
    schema = {
        "type": "OBJECT",
        "properties": {
            "scamDetected": {"type": "BOOLEAN"},
            "language": {"type": "STRING"},
            "agentReply": {"type": "STRING"},
            "intelligence": {
                "type": "OBJECT",
                "properties": {
                    "bankAccounts": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "upiIds": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "phishingLinks": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "phoneNumbers": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "suspiciousKeywords": {"type": "ARRAY", "items": {"type": "STRING"}}
                }
            }
        },
        "required": ["scamDetected", "language", "agentReply", "intelligence"]
    }

    resp = client.models.generate_content(
        model="gemini-3-flash-preview", 
        contents=prompt,
        config={"response_mime_type": "application/json", "response_schema": schema, "temperature": 0.1}
    )
    result = json.loads(resp.text)

    if result["scamDetected"]:
        bg.add_task(guvi_callback, {
            "sessionId": data.sessionId, 
            "scamDetected": True,
            "extractedIntelligence": result["intelligence"]
        })

    return result
