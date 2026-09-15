from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from backend.models.ai_schema import SecurityAnalysisResult, VulnerabilityFinding, PatchCandidate, OptimizationSuggestion

class VerifyPatchRequest(BaseModel):
    original_code: str = Field(..., description="Original vulnerable source code")
    patch_code: str = Field(..., description="Proposed replacement function or code patch")
    function_name: Optional[str] = Field(None, description="Name of the function being replaced")
    language: str = Field("c", description="Programming language (c, cpp, python, rust, java)")
    file_name: Optional[str] = Field(None, description="Original filename")
    vulnerability_id: Optional[str] = Field(None, description="Target vulnerability ID to verify")

class VerifyPatchResponse(BaseModel):
    is_verified: bool = Field(..., description="True if the patch compiles, eliminates the flaw, and introduces no regressions")
    syntax_valid: bool = Field(..., description="True if the patched code passed syntax checking")
    ir_generated: bool = Field(..., description="True if new LLVM IR was generated for the patched code")
    verified_code: str = Field(..., description="Complete patched source code")
    verification_message: str = Field(..., description="Detailed verification status explanation")
    remaining_issues: List[str] = Field(default_factory=list, description="Any lingering or new warnings detected")
    analysis_time_ms: float = Field(0.0, description="Verification processing time in milliseconds")

class ReportRequest(BaseModel):
    project_name: str = Field("FlawFix Audit", description="Project or repository name")
    file_name: str = Field("source_code.c", description="Target file name")
    language: str = Field("c", description="Programming language")
    analysis_result: SecurityAnalysisResult = Field(..., description="Vulnerability analysis findings")
    verified_patches: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="List of verified patches applied")
    original_code: Optional[str] = Field(None, description="Original source code snippet")

class ReportResponse(BaseModel):
    report_id: str = Field(..., description="Unique generated report ID")
    file_name: str = Field(..., description="PDF filename on server")
    file_path: str = Field(..., description="Absolute path to generated PDF")
    download_url: str = Field(..., description="API download URL for the PDF")
    file_size_bytes: int = Field(..., description="Size of generated PDF in bytes")
    generated_at: str = Field(..., description="Timestamp of generation")
