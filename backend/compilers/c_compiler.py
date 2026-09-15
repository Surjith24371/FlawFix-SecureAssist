import os
import re
import shutil
import tempfile
import subprocess
from typing import Optional, List
from backend.compilers.base_compiler import BaseCompiler
from backend.models.schema import SyntaxValidationResult, SyntaxErrorItem, LLVMIRResult

class CCompiler(BaseCompiler):
    """
    Compiler and Syntax Validator for C and C++ source code using Clang.
    """

    def __init__(self, is_cpp: bool = False):
        super().__init__("cpp" if is_cpp else "c")
        self.is_cpp = is_cpp
        self.clang_path = self._find_clang()

    def _find_clang(self) -> str:
        # Check standard installation locations or PATH
        default_paths = [
            r"C:\Program Files\LLVM\bin\clang++.exe" if self.is_cpp else r"C:\Program Files\LLVM\bin\clang.exe",
            r"C:\Program Files (x86)\LLVM\bin\clang++.exe" if self.is_cpp else r"C:\Program Files (x86)\LLVM\bin\clang.exe",
        ]
        for p in default_paths:
            if os.path.exists(p):
                return p
        
        # Fallback to PATH
        found = shutil.which("clang++" if self.is_cpp else "clang")
        if found:
            return found
        return "clang"

    def _parse_diagnostics(self, raw_stderr: str) -> (List[SyntaxErrorItem], List[SyntaxErrorItem]):
        errors = []
        warnings = []
        pattern = re.compile(r":(\d+):(\d+):\s*(fatal error|error|warning):\s*(.*)")

        for line in raw_stderr.splitlines():
            match = pattern.search(line)
            if match:
                line_num = int(match.group(1))
                col_num = int(match.group(2))
                diag_type = match.group(3).strip().lower()
                message = match.group(4).strip()

                item = SyntaxErrorItem(
                    line=line_num,
                    column=col_num,
                    message=message,
                    severity="error" if "error" in diag_type else "warning",
                    source="clang"
                )
                if "error" in diag_type:
                    errors.append(item)
                else:
                    warnings.append(item)

        return errors, warnings

    def validate_syntax(self, code: str, file_name: Optional[str] = None) -> SyntaxValidationResult:
        suffix = ".cpp" if self.is_cpp else ".c"
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        try:
            cmd = [
                self.clang_path,
                "-fsyntax-only",
                "-fno-color-diagnostics",
                "-Wall",
                temp_path
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            
            raw_output = res.stderr or res.stdout
            errors, warnings = self._parse_diagnostics(raw_output)

            # If returncode is non-zero and no errors were parsed by regex, add general error
            if res.returncode != 0 and not errors:
                errors.append(SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=raw_output.strip() or "Syntax validation failed",
                    severity="error",
                    source="clang"
                ))

            is_valid = len(errors) == 0 and res.returncode == 0
            return SyntaxValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                raw_output=raw_output
            )
        except Exception as e:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(line=1, column=1, message=f"Validator execution error: {str(e)}", severity="error", source="clang")],
                warnings=[],
                raw_output=str(e)
            )
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None) -> LLVMIRResult:
        # First ensure syntax is valid
        syntax_res = self.validate_syntax(code, file_name)
        if not syntax_res.is_valid:
            error_msgs = "; ".join([f"Line {e.line}: {e.message}" for e in syntax_res.errors])
            return LLVMIRResult(
                success=False,
                ir_code="",
                error=f"Syntax validation failed. Cannot generate LLVM IR: {error_msgs}"
            )

        suffix = ".cpp" if self.is_cpp else ".c"
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        temp_ll_path = temp_path + ".ll"

        try:
            cmd = [
                self.clang_path,
                "-S",
                "-emit-llvm",
                "-O0",
                "-g",
                "-Xclang",
                "-disable-O0-optnone",
                temp_path,
                "-o",
                temp_ll_path
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

            if res.returncode == 0 and os.path.exists(temp_ll_path):
                with open(temp_ll_path, "r", encoding="utf-8", errors="replace") as f:
                    ir_content = f.read()

                # Basic IR metadata extraction
                functions = re.findall(r"define\s+[^@]*@([a-zA-Z0-9_]+)\s*\(", ir_content)
                metadata = {
                    "functions": functions,
                    "function_count": len(functions),
                    "ir_line_count": len(ir_content.splitlines()),
                    "target_language": "C++" if self.is_cpp else "C"
                }

                return LLVMIRResult(
                    success=True,
                    ir_code=ir_content,
                    ir_file_path=temp_ll_path,
                    metadata=metadata
                )
            else:
                return LLVMIRResult(
                    success=False,
                    ir_code="",
                    error=f"Clang LLVM IR generation failed: {res.stderr}"
                )
        except Exception as e:
            return LLVMIRResult(
                success=False,
                ir_code="",
                error=f"Compiler exception: {str(e)}"
            )
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
