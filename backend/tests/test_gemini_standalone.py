import sys
import os
from dotenv import load_dotenv

sys.path.insert(0, "d:/FlawFix")
load_dotenv("d:/FlawFix/backend/.env")

from backend.ai.gemini_client import gemini_client
from backend.ai.prompts import SYSTEM_SECURITY_EXPERT_INSTRUCTION, build_vulnerability_analysis_prompt

code = """
#include <string.h>
void process_token(const char *raw_token) {
    char token_buf[8];
    strcpy(token_buf, raw_token);
}
"""

prompt = build_vulnerability_analysis_prompt(code, "c", "iSeVC summary mock", "test.c")

try:
    res = gemini_client.generate_json_response(prompt, SYSTEM_SECURITY_EXPERT_INSTRUCTION)
    print("SUCCESS JSON KEYS:", list(res.keys()))
    print("Is vulnerable:", res.get("is_vulnerable"))
except Exception as e:
    print("ERROR:", type(e), e)
