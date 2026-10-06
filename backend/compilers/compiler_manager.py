import os
import hashlib
import re
import ast
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
    Includes in-memory LRU/hash caching to avoid recompiling unchanged source code.
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
        self._cache: Dict[str, CompileResponse] = {}
        self._max_cache_entries = 64

    def detect_language(
        self,
        language: Optional[str] = None,
        file_name: Optional[str] = None,
        code: Optional[str] = None
    ) -> str:
        # Step 1: Check file extension if provided
        if file_name:
            ext = os.path.splitext(file_name)[1].lower().lstrip(".")
            if ext in ["c", "h"]:
                return "c"
            elif ext in ["cpp", "cc", "cxx", "hpp", "hh", "hxx"]:
                return "cpp"
            elif ext in ["py", "pyw"]:
                return "python"
            elif ext in ["rs"]:
                return "rust"
            elif ext in ["java"]:
                return "java"

        # Step 2: Content-based check: if code is clearly Python (imports, defs) and not C/C++ (#include), trust Python
        if code and code.strip():
            c_strip = code.strip()
            has_c_include = bool(re.search(r'^\s*#\s*include\s*[<"]', c_strip, re.MULTILINE))
            has_py_import = bool(re.search(r'^\s*(import\s+[a-zA-Z0-9_]|from\s+[a-zA-Z0-9_.]+\s+import)', c_strip, re.MULTILINE))
            has_py_def = bool(re.search(r'^\s*def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', c_strip, re.MULTILINE))
            has_py_main = '__name__' in c_strip and '__main__' in c_strip

            if (has_py_import or has_py_def or has_py_main) and not has_c_include:
                return "python"

            # Check if clearly Rust
            if not has_c_include and (re.search(r'\bfn\s+[a-zA-Z_][a-zA-Z0-9_]*\s*[<(]', c_strip) or 'let mut ' in c_strip or 'println!' in c_strip):
                return "rust"

            # Check if clearly Java
            if 'public class ' in c_strip or 'public static void main' in c_strip or 'System.out.print' in c_strip:
                return "java"

            # Check if clearly C++
            if has_c_include and ('std::' in c_strip or 'cout <<' in c_strip or 'cin >>' in c_strip or 'class ' in c_strip or 'namespace ' in c_strip):
                return "cpp"

            if has_c_include:
                return "c"

        # Step 3: Check explicit language parameter
        if language:
            norm_lang = language.lower().strip()
            if norm_lang in ["py"]:
                return "python"
            if norm_lang in ["rs"]:
                return "rust"
            if norm_lang in ["c++"]:
                return "cpp"
            if norm_lang in self.compilers:
                return norm_lang

        # Step 4: Fallback AST check if code parses cleanly as Python
        if code and code.strip():
            try:
                ast.parse(code)
                return "python"
            except Exception:
                pass

        # Default fallback to C
        return "c"

    def get_compiler(self, language: str) -> BaseCompiler:
        normalized = language.lower().strip()
        if normalized in self.compilers:
            return self.compilers[normalized]
        return self.compilers["c"]

    def _get_cache_key(self, code: str, language: str) -> str:
        h = hashlib.sha256(code.encode("utf-8")).hexdigest()
        return f"{language}_{h}"

    def validate_and_compile(
        self,
        code: str,
        language: Optional[str] = None,
        file_name: Optional[str] = None,
        use_cache: bool = True
    ) -> CompileResponse:
        """
        Executes the 2-step compilation pipeline:
        1. Strict syntax validation.
        2. LLVM IR generation (only executed if syntax validation passes, reusing validated status).
        Returns cached responses if the code is unchanged.
        """
        detected_lang = self.detect_language(language, file_name, code=code)
        cache_key = self._get_cache_key(code, detected_lang)

        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        compiler = self.get_compiler(detected_lang)

        # Execute optimized single-pass or two-pass compilation pipeline
        syntax_res, ir_res = compiler.compile_pipeline(code, file_name)

        response = CompileResponse(
            language=detected_lang,
            syntax_result=syntax_res,
            ir_result=ir_res
        )

        if len(self._cache) >= self._max_cache_entries:
            self._cache.pop(next(iter(self._cache)))
        self._cache[cache_key] = response

        return response

    def clear_cache(self):
        self._cache.clear()

# Global singleton instance
compiler_manager = CompilerManager()
