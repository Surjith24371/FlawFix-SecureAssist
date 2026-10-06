from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from backend.models.schema import SyntaxValidationResult
from backend.models.isevc_schema import iSeVCResult

class PatchCandidate(BaseModel):
    patch_id: str = Field(..., description="Unique patch identifier (e.g. 'patch_1', 'patch_2', 'patch_3')")
    title: str = Field(..., description="Short title describing the fix (e.g. 'Bounds-checked buffer copy')")
    description: str = Field(..., description="Explanation of how the patch fixes the security issue")
    patched_code: str = Field(..., description="Complete, secure replacement code for the affected function or block")
    optimization_notes: Optional[str] = Field(None, description="Performance or memory optimization details included in the patch")
    approach_type: Optional[str] = Field(None, description="Specific mitigation strategy (e.g. 'Defensive Validation', 'Safe API Replacement', 'Architectural Refactor')")
    is_recommended: Optional[bool] = Field(False, description="True if this patch is the primary recommended fix according to the remediation guidelines")


class VulnerabilityFinding(BaseModel):
    vulnerability_id: str = Field(..., description="Unique vulnerability ID (e.g. 'VULN-001')")
    title: str = Field(..., description="Vulnerability title (e.g. 'Buffer Overflow in process_input')")
    cwe_id: str = Field(..., description="Common Weakness Enumeration ID (e.g. 'CWE-120: Buffer Copy without Checking Size')")
    severity: str = Field(..., description="Severity level: 'Critical', 'High', 'Medium', or 'Low'")
    function_name: str = Field(..., description="Name of the vulnerable function")
    affected_lines: List[int] = Field(default_factory=list, description="Source code line numbers affected by this vulnerability")
    root_cause: str = Field(..., description="Explainable AI: In-depth explanation of why the vulnerability exists")
    security_impact: str = Field(..., description="Explainable AI: Potential impact if exploited by an attacker")
    recommendation: str = Field(..., description="Explainable AI: Secure coding guidelines to prevent similar flaws")
    patch_candidates: List[PatchCandidate] = Field(default_factory=list, description="AI-generated secure patch alternatives")

class OptimizationSuggestion(BaseModel):
    title: str = Field(..., description="Optimization title")
    description: str = Field(..., description="Explanation of suggested algorithmic or resource enhancement")
    impact: str = Field(..., description="Expected performance or memory benefit")

class SecurityAnalysisResult(BaseModel):
    is_vulnerable: bool = Field(..., description="True if one or more vulnerabilities were found")
    total_vulnerabilities: int = Field(0, description="Total count of detected vulnerabilities")
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list, description="Detailed vulnerability findings")
    general_optimizations: List[OptimizationSuggestion] = Field(default_factory=list, description="Code quality and performance optimization suggestions")
    summary: str = Field(..., description="Executive security assessment summary")
    analysis_time_ms: float = Field(0.0, description="Analysis processing time in milliseconds")

class FullAnalysisRequest(BaseModel):
    code: str = Field(..., description="Source code text to analyze")
    language: str = Field("c", description="Language identifier (c, cpp, python, rust, java)")
    file_name: Optional[str] = Field(None, description="Original filename")

class FullAnalysisResponse(BaseModel):
    language: str
    file_name: Optional[str] = None
    syntax_result: SyntaxValidationResult
    ir_generated: bool
    isevc: Optional[iSeVCResult] = None
    analysis_result: Optional[SecurityAnalysisResult] = None
    error: Optional[str] = None
