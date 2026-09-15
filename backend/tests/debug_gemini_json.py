import sys
import os
sys.path.insert(0, "d:/FlawFix")
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv("d:/FlawFix/backend/.env")
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

from backend.ai.prompts import SYSTEM_SECURITY_EXPERT_INSTRUCTION, build_vulnerability_analysis_prompt

code = """
#include <string.h>
void process_token(const char *raw_token) {
    char token_buf[8];
    strcpy(token_buf, raw_token);
}
"""

prompt = build_vulnerability_analysis_prompt(code, "c", "iSeVC test", "token.c")

config = types.GenerateContentConfig(
    system_instruction=SYSTEM_SECURITY_EXPERT_INSTRUCTION,
    response_mime_type="application/json",
    temperature=0.1
)

try:
    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=prompt,
        config=config
    )
    print("Raw Response text length:", len(response.text) if response.text else "None")
    print("Raw Response text snippet:\n", response.text[:300] if response.text else "EMPTY")
    parsed = json.loads(response.text, strict=False)
    print("Parsed successfully with strict=False! Keys:", list(parsed.keys()))
    print("Vulnerabilities count:", len(parsed.get("vulnerabilities", [])))
    print("Top vulnerability:", parsed["vulnerabilities"][0]["title"])
except Exception as e:
    print("Exception occurred:", type(e), e)
    import traceback
    traceback.print_exc()
