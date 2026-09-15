import os
import sys
import subprocess
from dotenv import load_dotenv

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

print("=== FlawFix Environment Verification ===")

# 1. Check Python & Virtualenv
print(f"[OK] Python version: {sys.version.split()[0]}")

# 2. Check dotenv & Gemini Key
load_dotenv("d:/FlawFix/backend/.env")
api_key = os.getenv("GEMINI_API_KEY")
if api_key and len(api_key.strip()) > 10:
    print(f"[OK] Gemini API Key loaded: {api_key[:6]}...{api_key[-4:]}")
else:
    print("[!] Warning: GEMINI_API_KEY is missing or empty in backend/.env")

# 3. Test Gemini API Connectivity
try:
    from google import genai
    client = genai.Client(api_key=api_key)
    # Try gemini-2.0-flash
    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents="Say 'FlawFix SecureAssist AI ready!'"
    )
    print(f"[OK] Gemini API Connection: SUCCESS -> {response.text.strip()}")
except Exception as e:
    print(f"[!] Gemini API Connection note: {e}")

# 4. Test ReportLab
try:
    import reportlab
    print(f"[OK] ReportLab PDF Generator: SUCCESS (v{reportlab.__version__})")
except ImportError as e:
    print(f"[X] ReportLab missing: {e}")

# 5. Test Clang LLVM IR Generation
try:
    test_c_file = "d:/FlawFix/backend/test_dummy.c"
    test_ll_file = "d:/FlawFix/backend/test_dummy.ll"
    with open(test_c_file, "w") as f:
        f.write("int main() { int x = 42; return x; }\n")
    
    clang_path = "C:\\Program Files\\LLVM\\bin\\clang.exe"
    cmd = [clang_path, "-S", "-emit-llvm", "-O0", test_c_file, "-o", test_ll_file]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0 and os.path.exists(test_ll_file):
        with open(test_ll_file, "r") as f:
            content = f.read()
        print(f"[OK] Clang LLVM IR Generator: SUCCESS -> Generated {len(content)} bytes of LLVM IR")
        if os.path.exists(test_c_file):
            os.remove(test_c_file)
        if os.path.exists(test_ll_file):
            os.remove(test_ll_file)
    else:
        print(f"[X] Clang error: {res.stderr}")
except Exception as e:
    print(f"[X] Clang compilation test error: {e}")

# 6. Test Node / Extension environment
try:
    node_path = "C:\\Program Files\\nodejs\\node.exe"
    res = subprocess.run([node_path, "-v"], capture_output=True, text=True)
    print(f"[OK] Node.js Extension Engine: SUCCESS ({res.stdout.strip()})")
except Exception as e:
    print(f"[!] Node.js check error: {e}")

print("=========================================")
