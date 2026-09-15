import os
import re
import json
import shutil
import tempfile
import subprocess
from typing import Optional, List
from backend.compilers.base_compiler import BaseCompiler
from backend.models.schema import SyntaxValidationResult, SyntaxErrorItem, LLVMIRResult

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

    def _parse_diagnostics(self, raw_stderr: str) -> (List[SyntaxErrorItem], List[SyntaxErrorItem]):
        errors = []
        warnings = []
        for line in raw_stderr.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    msg = obj.get("message", "")
                    level = obj.get("level", "error")
                    spans = obj.get("spans", [])
                    line_no = spans[0].get("line_start", 1) if spans else 1
                    col_no = spans[0].get("column_start", 1) if spans else 1

                    item = SyntaxErrorItem(
                        line=line_no,
                        column=col_no,
                        message=msg,
                        severity="error" if level == "error" else "warning",
                        source="rustc"
                    )
                    if level == "error":
                        errors.append(item)
                    else:
                        warnings.append(item)
                except Exception:
                    pass
            elif "error:" in line or "error[" in line:
                errors.append(SyntaxErrorItem(
                    line=1, column=1, message=line, severity="error", source="rustc"
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
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            errors, warnings = self._parse_diagnostics(res.stderr)

            is_valid = len(errors) == 0 and res.returncode == 0
            return SyntaxValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                raw_output=res.stderr or res.stdout
            )
        except Exception as e:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(line=1, column=1, message=f"Rust validator error: {str(e)}", severity="error", source="rustc")],
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

    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None) -> LLVMIRResult:
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
                "-g",
                temp_path,
                "-o", temp_ll_path
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

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
                    error=f"Rust LLVM IR generation failed: {res.stderr}"
                )
        except Exception as e:
            return LLVMIRResult(
                success=False,
                ir_code="",
                error=f"Rust compiler exception: {str(e)}"
            )
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
