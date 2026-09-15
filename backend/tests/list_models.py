import os
from dotenv import load_dotenv
from google import genai

load_dotenv("d:/FlawFix/backend/.env")
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

print("=== Available Gemini Models ===")
for m in client.models.list():
    if "flash" in m.name or "pro" in m.name:
        print(f"- {m.name} (display: {m.display_name})")
