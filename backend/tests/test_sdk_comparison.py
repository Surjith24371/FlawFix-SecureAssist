import os
import time
from dotenv import load_dotenv

load_dotenv("d:/FlawFix/backend/.env")
api_key = os.getenv("GEMINI_API_KEY")

print("--- Testing google.generativeai SDK ---")
try:
    import google.generativeai as legacy_genai
    legacy_genai.configure(api_key=api_key)
    for model_name in ["gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]:
        try:
            t0 = time.time()
            m = legacy_genai.GenerativeModel(model_name)
            res = m.generate_content("Say 'Hello from legacy SDK!' in 3 words")
            print(f"[OK] {model_name}: {res.text.strip()} ({round((time.time()-t0)*1000)}ms)")
            break
        except Exception as e:
            print(f"[X] {model_name} failed: {e}")
except Exception as e:
    print(f"[X] legacy_genai failed: {e}")

print("\n--- Testing google.genai (New SDK) ---")
try:
    from google import genai
    client = genai.Client(api_key=api_key)
    for model_name in ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-flash-latest"]:
        try:
            t0 = time.time()
            res = client.models.generate_content(
                model=model_name,
                contents="Say 'Hello from new SDK!' in 3 words"
            )
            print(f"[OK] {model_name}: {res.text.strip()} ({round((time.time()-t0)*1000)}ms)")
            break
        except Exception as e:
            print(f"[X] {model_name} failed: {e}")
except Exception as e:
    print(f"[X] genai client failed: {e}")
