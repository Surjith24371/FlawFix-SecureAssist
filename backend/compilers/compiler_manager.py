import os
from typing import Optional, Dict
from backend.compilers.base_compiler import BaseCompiler
from backend.compilers.c_compiler import CCompiler
from backend.compilers.python_compiler import PythonCompiler
from backend.compilers.rust_compiler import RustCompiler
from backend.compilers.java_compiler import JavaCompiler
from backend.models.schema import CompileResponse, SyntaxValidationResult, LLVMIRResult

class CompilerManager:
    """
    Central manager for language detection, syntax validation, and LLVM IR generation.
    Enforces the rule: Syntax check MUST pass before LLVM IR is generated.
    """

    def __init__(self):
        self.compilers: Dict[str, BaseCompiler] = {
            "c": CCompiler(is_cpp=False),
            "cpp": CCompiler(is_cpp=True),
            "c++": CCompiler(is_cpp=True),
            "python": PythonCompiler(),
            "py": PythonCompiler(),
            "rust": RustCompiler(),
            "rs": RustCompiler(),
            "java": JavaCompiler()
        }

    def detect_language(self, language: Optional[str], file_name: Optional[str]) -> str:
        if language and language.lower().strip() in self.compilers:
            return language.lower().strip()
        
        if file_name:
            ext = os.path.splitext(file_name)[1].lower().lstrip(".")
            if ext in ["c", "h"]:
                return "c"
            elif ext in ["cpp", "cc", "cxx", "hpp"]:
                return "cpp"
            elif ext in ["py", "pyw"]:
                return "python"
            elif ext in ["rs"]:
                return "rust"
            elif ext in ["java"]:
                return "java"
        
        # Default fallback to C
        return "c"

    def get_compiler(self, language: str) -> BaseCompiler:
        normalized = language.lower().strip()
        if normalized in self.compilers:
            return self.compilers[normalized]
        return self.compilers["c"]

    def validate_and_compile(
        self,
        code: str,
        language: Optional[str] = None,
        file_name: Optional[str] = None
    ) -> CompileResponse:
        """
        Executes the 2-step compilation pipeline:
        1. Strict syntax validation.
        2. LLVM IR generation (only executed if syntax validation passes).
        """
        detected_lang = self.detect_language(language, file_name)
        compiler = self.get_compiler(detected_lang)

        # Step 1: Validate Syntax
        syntax_res = compiler.validate_syntax(code, file_name)

        # Step 2: If invalid, return immediately with syntax errors and no IR
        if not syntax_res.is_valid:
            return CompileResponse(
                language=detected_lang,
                syntax_result=syntax_res,
                ir_result=None
            )

        # Step 3: Syntax is valid, generate LLVM IR
        ir_res = compiler.generate_llvm_ir(code, file_name)

        return CompileResponse(
            language=detected_lang,
            syntax_result=syntax_res,
            ir_result=ir_res
        )

# Global singleton instance
compiler_manager = CompilerManager()
