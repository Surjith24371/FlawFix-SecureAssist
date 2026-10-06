from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class SyntaxErrorItem(BaseModel):
    line: int = Field(..., description="Line number of the error (1-indexed)")
    column: int = Field(1, description="Column offset of the error (1-indexed)")
    message: str = Field(..., description="Error message description")
    severity: str = Field("error", description="'error' or 'warning'")
    source: Optional[str] = Field(None, description="Compiler or validator source")
    error_type: Optional[str] = Field("SyntaxError", description="Error category or type")
    explanation: Optional[str] = Field(None, description="Clear human-readable explanation")
    original_message: Optional[str] = Field(None, description="Original raw compiler/parser diagnostic message")


class SyntaxValidationResult(BaseModel):
    is_valid: bool = Field(..., description="True if no syntax errors were found")
    errors: List[SyntaxErrorItem] = Field(default_factory=list, description="List of detected syntax errors")
    warnings: List[SyntaxErrorItem] = Field(default_factory=list, description="List of detected warnings")
    raw_output: str = Field("", description="Raw stderr/stdout from validator")

class LLVMIRResult(BaseModel):
    success: bool = Field(..., description="True if LLVM IR generation succeeded")
    ir_code: str = Field("", description="Generated LLVM IR text (.ll)")
    ir_file_path: Optional[str] = Field(None, description="Path to temporary .ll file")
    error: Optional[str] = Field(None, description="Error message if generation failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as function count, lines, etc.")

class CompileRequest(BaseModel):
    code: str = Field(..., description="Source code text to validate and compile")
    language: str = Field("c", description="Language identifier (c, cpp, python, rust, java)")
    file_name: Optional[str] = Field(None, description="Original filename or placeholder")

class CompileResponse(BaseModel):
    language: str
    syntax_result: SyntaxValidationResult
    ir_result: Optional[LLVMIRResult] = None
