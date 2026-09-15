# 🛡️ FlawFix SecureAssist

> **AI-Powered Visual Studio Code Extension for Real-Time Vulnerability Detection and Intelligent Secure Patch Generation**  
> *Master of Computer Applications (MCA) Project — APJ Abdul Kalam Technological University*

---

## 📖 Overview

**FlawFix SecureAssist** is a next-generation software security platform that integrates compiler-level semantic analysis with Google Gemini LLM reasoning. Unlike traditional static analysis tools that rely purely on syntactic pattern-matching, FlawFix compiles source code into **LLVM Intermediate Representation (LLVM IR)**, extracts **Intermediate Semantic Vulnerability Contexts (iSeVCs)**, and performs deep data-flow and control-flow reasoning.

```
Detect (Syntax Check) ➔ Analyze (LLVM IR & iSeVC) ➔ Explain (XAI) ➔ Patch (AI Code Optimizer) ➔ Verify (Auto-Recompile) ➔ Report (PDF)
```

---

## 🚀 Key Modules & Architecture

1. **Pre-flight Syntax Validator** (`backend/compilers/`): Catches and flags syntax errors before compilation.
2. **LLVM IR Generator** (`backend/compilers/`): Generates unoptimized, debug-annotated LLVM IR via Clang, rustc, GraalVM, and Nuitka.
3. **iSeVC Feature Extractor** (`backend/extractor/`): Extracts BasicBlock CFGs, def-use data dependency chains, memory operations, and sensitive API calls while pruning >54% token overhead.
4. **AI Vulnerability Detector & XAI** (`backend/ai/`): Identifies CWE vulnerabilities with root-cause explanations, CVSS severity ratings, and impact assessments.
5. **Secure Patch Generator & AI Optimizer** (`backend/ai/`): Generates drop-in replacement functions and algorithmic optimizations.
6. **Automated Patch Verifier** (`backend/verifier/`): Re-compiles patched code to LLVM IR and semantically verifies vulnerability elimination.
7. **ReportLab PDF Generator** (`backend/reporter/`): Generates publication-grade PDF audit reports.
8. **VS Code Extension Client** (`extension/`): In-editor squiggly diagnostics, interactive Activity Bar Sidebar, side-by-side patch diff previewing, and one-click apply & verify.

---

## 🛠️ Getting Started

### 1. Start the Backend Service
In a terminal, run:
```powershell
d:\FlawFix\venv\Scripts\python.exe d:\FlawFix\backend\app.py
```
*(Or simply double-click `run_backend.bat`)*

The server will start at: `http://127.0.0.1:8000`  
Interactive API Docs: `http://127.0.0.1:8000/docs`

### 2. Launch the VS Code Extension
1. Open the `d:\FlawFix\extension` folder in VS Code.
2. Press **`F5`** (or go to **Run and Debug** ➔ **Launch Extension**).
3. A new **Extension Development Host** VS Code window will open.
4. Open any `.c`, `.py`, or `.rs` file (e.g. `backend/tests/samples/buffer_overflow.c`).
5. Click **⚡ Scan Active File** in the FlawFix Sidebar in the Activity Bar!

---

## 🧪 Testing the Pipeline

Run the comprehensive automated test suites:

```powershell
# 1. Test Compiler Syntax Validation & LLVM IR Generation
d:\FlawFix\venv\Scripts\python.exe d:\FlawFix\backend\tests\test_compilers.py

# 2. Test iSeVC Semantic Feature Extraction
d:\FlawFix\venv\Scripts\python.exe d:\FlawFix\backend\tests\test_isevc.py

# 3. Test AI Vulnerability Detection & Patch Generation
d:\FlawFix\venv\Scripts\python.exe d:\FlawFix\backend\tests\test_ai_detection.py

# 4. Test Patch Verification & ReportLab PDF Generator
d:\FlawFix\venv\Scripts\python.exe d:\FlawFix\backend\tests\test_verifier_and_reporter.py

# 5. Full End-to-End FastAPI Test Suite
d:\FlawFix\venv\Scripts\python.exe d:\FlawFix\backend\tests\test_api.py
```

---

## 📜 Academic Reference & Citation
* Based on the research thesis: **FlawFix: Language-Agnostic Vulnerability Detection and Explanation using LLVM IR and Large Language Models**, Government Engineering College Thrissur (2026).
