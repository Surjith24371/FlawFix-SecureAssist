import os
import re
import json
import shutil
import tempfile
import subprocess
from typing import Optional, List, Tuple
from backend.compilers.base_compiler import BaseCompiler
from backend.models.schema import SyntaxValidationResult, SyntaxErrorItem, LLVMIRResult

COMPILER_TIMEOUT = int(os.environ.get("FLAWFIX_COMPILER_TIMEOUT", "25"))

class RustCompiler(BaseCompiler):
    """
    Compiler and Syntax Validator for Rust source code using rustc.
    """

    def __init__(self):
        super().__init__("rust")
        self.rustc_path = self._find_rustc()

    def _find_rustc(self) -> str:
        user_cargo = os.path.expanduser(r"~\.cargo\bin\rustc.exe")
        if os.path.exists(user_cargo):
            return user_cargo
        found = shutil.which("rustc")
        if found:
            return found
        return "rustc"

    def _parse_diagnostics(self, raw_stderr: str) -> Tuple[List[SyntaxErrorItem], List[SyntaxErrorItem]]:
        errors = []
        warnings = []
        for line in raw_stderr.splitlines():
            line_str = line.strip()
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    obj = json.loads(line_str)
                    msg = obj.get("message", "")
                    level = obj.get("level", "error")
                    spans = obj.get("spans", [])
                    line_no = spans[0].get("line_start", 1) if spans else 1
                    col_no = spans[0].get("column_start", 1) if spans else 1
                    code_info = obj.get("code")
                    err_code = code_info.get("code") if isinstance(code_info, dict) else "RustError"

                    item = SyntaxErrorItem(
                        line=line_no,
                        column=col_no,
                        message=msg,
                        severity="error" if level == "error" else "warning",
                        source="rustc",
                        error_type=err_code,
                        explanation=f"Rust compiler error [{err_code}]: {msg}",
                        original_message=msg
                    )
                    if level == "error":
                        errors.append(item)
                    else:
                        warnings.append(item)
                except Exception:
                    pass
            elif "error:" in line_str or "error[" in line_str:
                errors.append(SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=line_str,
                    severity="error",
                    source="rustc",
                    error_type="RustError",
                    explanation=line_str,
                    original_message=line_str
                ))
        return errors, warnings

    def validate_syntax(self, code: str, file_name: Optional[str] = None) -> SyntaxValidationResult:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        try:
            cmd = [
                self.rustc_path,
                "--error-format=json",
                "--emit=metadata",
                temp_path,
                "-o", temp_path + ".rmeta"
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMPILER_TIMEOUT
            )
            errors, warnings = self._parse_diagnostics(res.stderr)

            is_valid = len(errors) == 0 and res.returncode == 0
            return SyntaxValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                raw_output=res.stderr or res.stdout
            )
        except subprocess.TimeoutExpired:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Rust syntax validation timed out after {COMPILER_TIMEOUT} seconds.",
                    severity="error",
                    source="rustc",
                    error_type="CompilerTimeout",
                    explanation="rustc took too long to validate syntax.",
                    original_message="subprocess.TimeoutExpired"
                )],
                warnings=[],
                raw_output="TimeoutExpired"
            )
        except Exception as e:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Rust validator error: {str(e)}",
                    severity="error",
                    source="rustc",
                    error_type="InternalError",
                    explanation=str(e),
                    original_message=str(e)
                )],
                warnings=[],
                raw_output=str(e)
            )
        finally:
            for p in [temp_path, temp_path + ".rmeta"]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None, already_validated: bool = False) -> LLVMIRResult:
        if not already_validated:
            syntax_res = self.validate_syntax(code, file_name)
            if not syntax_res.is_valid:
                error_msgs = "; ".join([f"Line {e.line}: {e.message}" for e in syntax_res.errors])
                return LLVMIRResult(
                    success=False,
                    ir_code="",
                    error=f"Rust syntax validation failed: {error_msgs}"
                )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        temp_ll_path = temp_path + ".ll"

        try:
            cmd = [
                self.rustc_path,
                "--emit=llvm-ir",
                "-C", "opt-level=0",
                "-C", "debuginfo=1",
                temp_path,
                "-o", temp_ll_path
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMPILER_TIMEOUT
            )

            if res.returncode == 0 and os.path.exists(temp_ll_path):
                with open(temp_ll_path, "r", encoding="utf-8", errors="replace") as f:
                    ir_content = f.read()

                functions = re.findall(r"define\s+[^@]*@([a-zA-Z0-9_]+)\s*\(", ir_content)
                return LLVMIRResult(
                    success=True,
                    ir_code=ir_content,
                    ir_file_path=temp_ll_path,
                    metadata={"functions": functions, "function_count": len(functions), "target_language": "Rust"}
                )
            else:
                return LLVMIRResult(
                    success=False,
                    ir_code="",
                    error=f"Rust LLVM IR generation failed: {res.stderr.strip() or res.stdout.strip()}"
                )
        except subprocess.TimeoutExpired:
            return LLVMIRResult(
                success=False,
                ir_code="",
                error="LLVM IR generation timed out while processing the source code. Security analysis could not be completed."
            )
        except Exception as e:
            return LLVMIRResult(
                success=False,
                ir_code="",
                error=f"Rust compiler exception: {str(e)}"
            )
        finally:
            for p in [temp_path, temp_ll_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

    def compile_pipeline(self, code: str, file_name: Optional[str] = None) -> Tuple[SyntaxValidationResult, Optional[LLVMIRResult]]:
        """
        Executes an optimized single-pass compilation pipeline using rustc.
        Validates syntax and produces LLVM IR in a single compiler invocation.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        temp_ll_path = temp_path + ".ll"

        try:
            cmd = [
                self.rustc_path,
                "--emit=llvm-ir",
                "-C", "opt-level=0",
                "-C", "debuginfo=1",
                "--error-format=json",
                temp_path,
                "-o", temp_ll_path
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMPILER_TIMEOUT
            )

            errors, warnings = self._parse_diagnostics(res.stderr)

            if res.returncode != 0:
                if not errors:
                    errors.append(SyntaxErrorItem(
                        line=1,
                        column=1,
                        message=res.stderr.strip() or "Rust compilation failed",
                        severity="error",
                        source="rustc",
                        error_type="RustError",
                        explanation=res.stderr.strip() or "Rust compilation error",
                        original_message=res.stderr.strip()
                    ))
                return SyntaxValidationResult(
                    is_valid=False,
                    errors=errors,
                    warnings=warnings,
                    raw_output=res.stderr or res.stdout
                ), None

            syntax_res = SyntaxValidationResult(
                is_valid=True,
                errors=[],
                warnings=warnings,
                raw_output=res.stderr or res.stdout
            )

            if os.path.exists(temp_ll_path):
                with open(temp_ll_path, "r", encoding="utf-8", errors="replace") as f:
                    ir_content = f.read()

                functions = re.findall(r"define\s+[^@]*@([a-zA-Z0-9_]+)\s*\(", ir_content)
                ir_res = LLVMIRResult(
                    success=True,
                    ir_code=ir_content,
                    ir_file_path=temp_ll_path,
                    metadata={"functions": functions, "function_count": len(functions), "target_language": "Rust"}
                )
                return syntax_res, ir_res
            else:
                return syntax_res, LLVMIRResult(
                    success=False,
                    ir_code="",
                    error="LLVM IR file was not generated by rustc."
                )

        except subprocess.TimeoutExpired:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Rust syntax validation timed out after {COMPILER_TIMEOUT} seconds.",
                    severity="error",
                    source="rustc",
                    error_type="CompilerTimeout",
                    explanation="rustc took too long to validate syntax.",
                    original_message="subprocess.TimeoutExpired"
                )],
                warnings=[],
                raw_output="TimeoutExpired"
            ), None
        except Exception as e:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Rust validator error: {str(e)}",
                    severity="error",
                    source="rustc",
                    error_type="InternalError",
                    explanation=str(e),
                    original_message=str(e)
                )],
                warnings=[],
                raw_output=str(e)
            ), None
        finally:
            for p in [temp_path, temp_ll_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
