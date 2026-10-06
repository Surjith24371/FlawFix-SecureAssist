import os
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models.schema import (
    CompileRequest,
    CompileResponse,
    SyntaxValidationResult
)
from backend.models.isevc_schema import (
    iSeVCRequest,
    iSeVCResponse,
    iSeVCResult
)
from backend.models.ai_schema import (
    FullAnalysisRequest,
    FullAnalysisResponse,
    SecurityAnalysisResult
)
from backend.models.verification_schema import (
    VerifyPatchRequest,
    VerifyPatchResponse,
    ReportRequest,
    ReportResponse
)
from backend.compilers.compiler_manager import compiler_manager
from backend.extractor.isevc_builder import isevc_builder
from backend.verifier.patch_verifier import patch_verifier
from backend.reporter.pdf_generator import pdf_report_generator
from fastapi.responses import FileResponse

load_dotenv()

app = FastAPI(
    title="FlawFix SecureAssist Backend Engine",
    description="AI-Powered Vulnerability Detection, Semantic LLVM IR Analysis, and Patch Generation API",
    version="1.0.0"
)

# Enable CORS for VS Code Extension Webview communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "FlawFix SecureAssist Engine",
        "version": "1.0.0",
        "active_compilers": list(compiler_manager.compilers.keys())
    }

@app.post("/api/validate-syntax", response_model=SyntaxValidationResult)
def validate_syntax(request: CompileRequest):
    """
    Validates code syntax without generating LLVM IR.
    """
    detected_lang = compiler_manager.detect_language(request.language, request.file_name, code=request.code)
    compiler = compiler_manager.get_compiler(detected_lang)
    result = compiler.validate_syntax(request.code, request.file_name)
    return result

@app.post("/api/generate-ir", response_model=CompileResponse)
def generate_ir(request: CompileRequest):
    """
    Pipeline step 1 & 2:
    Validates syntax first. If valid, generates LLVM IR. If invalid, stops and returns syntax errors.
    """
    result = compiler_manager.validate_and_compile(
        code=request.code,
        language=request.language,
        file_name=request.file_name
    )
    return result

@app.post("/api/extract-isevc", response_model=iSeVCResponse)
def extract_isevc(request: iSeVCRequest):
    """
    Pipeline step 1, 2 & 3 (Module 5.3.3):
    1. Validates syntax
    2. Compiles to LLVM IR (or uses provided IR)
    3. Extracts Intermediate Semantic Vulnerability Contexts (iSeVC)
    """
    detected_lang = compiler_manager.detect_language(request.language, request.file_name, code=request.code)

    # If IR code is directly provided
    if request.ir_code and request.ir_code.strip():
        isevc_res = isevc_builder.build_isevc(request.ir_code, request.code)
        return iSeVCResponse(
            language=detected_lang,
            is_valid_syntax=True,
            ir_generated=True,
            isevc=isevc_res
        )

    # Otherwise run compilation pipeline
    comp_res = compiler_manager.validate_and_compile(
        code=request.code,
        language=detected_lang,
        file_name=request.file_name
    )

    if not comp_res.syntax_result.is_valid:
        error_msgs = "; ".join([f"Line {e.line}: {e.message}" for e in comp_res.syntax_result.errors])
        return iSeVCResponse(
            language=detected_lang,
            is_valid_syntax=False,
            ir_generated=False,
            isevc=None,
            error=f"Syntax error: {error_msgs}"
        )

    if not comp_res.ir_result or not comp_res.ir_result.success:
        return iSeVCResponse(
            language=detected_lang,
            is_valid_syntax=True,
            ir_generated=False,
            isevc=None,
            error=comp_res.ir_result.error if comp_res.ir_result else "IR generation failed"
        )

    # Extract iSeVC from generated LLVM IR
    isevc_res = isevc_builder.build_isevc(comp_res.ir_result.ir_code, request.code)

    return iSeVCResponse(
        language=detected_lang,
        is_valid_syntax=True,
        ir_generated=True,
        isevc=isevc_res
    )

@app.post("/api/analyze-vulnerabilities", response_model=FullAnalysisResponse)
def analyze_vulnerabilities(request: FullAnalysisRequest):
    """
    Full End-to-End Security Analysis Pipeline (Modules 5.3.2 -> 5.3.6):
    1. Pre-flight Syntax Validation
    2. LLVM IR Generation
    3. iSeVC Feature Extraction & Pruning
    4. AI-Based Vulnerability Detection (Gemini)
    5. Explainable AI (XAI) Root Cause & Impact
    6. Intelligent Secure Patch Generation & Code Optimization
    """
    from backend.ai.vulnerability_detector import vulnerability_detector
    return vulnerability_detector.analyze_source_code(request)

@app.post("/api/verify-patch", response_model=VerifyPatchResponse)
def verify_patch(request: VerifyPatchRequest):
    """
    Automated Patch Verification Pipeline (Module 5.3.7 & 5.3.8):
    1. Integrates patch candidate into code
    2. Validates syntax of patched code
    3. Generates new LLVM IR & iSeVC
    4. Performs semantic verification with Gemini to confirm vulnerability elimination
    """
    return patch_verifier.verify_patch(request)

@app.post("/api/generate-report", response_model=ReportResponse)
def generate_report(request: ReportRequest):
    """
    Comprehensive Security Audit PDF Report Generator using ReportLab (Module 4.6.8).
    """
    return pdf_report_generator.generate_report(request)

@app.get("/api/reports/{file_name}")
def download_report(file_name: str):
    """
    Serves the generated ReportLab PDF document.
    """
    report_dir = os.path.join(os.path.dirname(__file__), "reports")
    file_path = os.path.join(report_dir, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(file_path, media_type="application/pdf", filename=file_name)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "127.0.0.1")
    print(f"Starting FlawFix SecureAssist server on http://{host}:{port}")
    uvicorn.run("backend.app:app", host=host, port=port, reload=True)
