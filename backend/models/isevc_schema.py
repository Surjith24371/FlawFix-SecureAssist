from typing import List, Optional, Dict, Any, Set
from pydantic import BaseModel, Field

class IRInstruction(BaseModel):
    raw_text: str = Field(..., description="Original raw LLVM IR instruction line")
    opcode: str = Field(..., description="LLVM opcode (e.g. alloca, load, store, call, br, getelementptr)")
    result_var: Optional[str] = Field(None, description="Assigned register/variable (e.g. %1, %res)")
    operands: List[str] = Field(default_factory=list, description="Instruction operand registers or constants")
    source_line: Optional[int] = Field(None, description="Resolved source code line number from DILocation")
    source_column: Optional[int] = Field(None, description="Resolved source code column")
    is_memory_op: bool = Field(False, description="True for alloca, load, store, getelementptr")
    is_pointer_op: bool = Field(False, description="True if operating on pointer types")
    is_call: bool = Field(False, description="True for function calls")
    called_function: Optional[str] = Field(None, description="Name of called function if is_call is True")
    is_branch: bool = Field(False, description="True for conditional or unconditional branch instructions")
    is_security_sensitive: bool = Field(False, description="True if flagged as potential vulnerability site")
    security_tag: Optional[str] = Field(None, description="Category tag (e.g., 'dangerous_call', 'buffer_alloca', 'pointer_arithmetic')")

class BasicBlockContext(BaseModel):
    label: str = Field(..., description="Basic block identifier label")
    instructions: List[IRInstruction] = Field(default_factory=list, description="Instructions in this block")
    predecessors: List[str] = Field(default_factory=list, description="Preceding basic block labels")
    successors: List[str] = Field(default_factory=list, description="Successor basic block labels")
    source_lines: List[int] = Field(default_factory=list, description="Unique source code lines in this block")

class FunctionSemanticContext(BaseModel):
    function_name: str = Field(..., description="Function symbol name")
    return_type: str = Field(..., description="Return type specification")
    arguments: List[str] = Field(default_factory=list, description="Function arguments")
    basic_blocks: List[BasicBlockContext] = Field(default_factory=list, description="CFG Basic blocks")
    memory_allocations: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted memory allocations (alloca/malloc)")
    pointer_operations: List[Dict[str, Any]] = Field(default_factory=list, description="Pointer loads, stores, indexing")
    critical_calls: List[Dict[str, Any]] = Field(default_factory=list, description="Calls to dangerous or security-sensitive functions")
    source_lines_covered: List[int] = Field(default_factory=list, description="All source lines mapped to this function")

class iSeVCResult(BaseModel):
    success: bool = Field(..., description="True if context extraction succeeded")
    functions: List[FunctionSemanticContext] = Field(default_factory=list, description="Extracted function contexts")
    global_symbols: List[str] = Field(default_factory=list, description="Global variables and type declarations")
    semantic_summary: str = Field("", description="Optimized, pruned semantic context ready for LLM prompt")
    raw_ir_size_bytes: int = Field(0, description="Size of raw LLVM IR input")
    pruned_size_bytes: int = Field(0, description="Size of pruned semantic context")
    reduction_percentage: float = Field(0.0, description="Token/character reduction achieved by iSeVC")
    error: Optional[str] = Field(None, description="Error message if extraction failed")

class iSeVCRequest(BaseModel):
    code: str = Field(..., description="Source code text")
    language: str = Field("c", description="Language identifier (c, cpp, python, rust, java)")
    file_name: Optional[str] = Field(None, description="Filename")
    ir_code: Optional[str] = Field(None, description="Optional pre-generated LLVM IR code")

class iSeVCResponse(BaseModel):
    language: str
    is_valid_syntax: bool
    ir_generated: bool
    isevc: Optional[iSeVCResult] = None
    error: Optional[str] = None
