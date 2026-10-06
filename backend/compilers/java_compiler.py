import os
import re
import shutil
import tempfile
import subprocess
from typing import Optional, List, Tuple
from backend.compilers.base_compiler import BaseCompiler
from backend.models.schema import SyntaxValidationResult, SyntaxErrorItem, LLVMIRResult

COMPILER_TIMEOUT = int(os.environ.get("FLAWFIX_COMPILER_TIMEOUT", "25"))

def categorize_java_diagnostic(msg: str) -> Tuple[str, str]:
    msg_l = msg.lower()
    if "';' expected" in msg_l:
        return "MissingSemicolon", "A semicolon ';' is missing at the end of the statement or declaration."
    if "cannot find symbol" in msg_l:
        return "SymbolNotFound", "The compiler cannot resolve this variable, method, or class name."
    if "incompatible types" in msg_l:
        return "TypeMismatch", "Type mismatch: incompatible data types in assignment or return statement."
    if "expected" in msg_l and any(c in msg_l for c in ["')'", "'}'", "'('", "'{'"]):
        return "UnclosedDelimiter", f"Missing delimiter: {msg}"
    if "illegal start of expression" in msg_l or "illegal start of type" in msg_l:
        return "SyntaxError", "Illegal start of expression or type declaration."
    return "SyntaxError", msg

class JavaCompiler(BaseCompiler):
    """
    Compiler and Syntax Validator for Java source code using javac and Bytecode IR.
    """

    def __init__(self):
        super().__init__("java")
        self.javac_path = self._find_javac()

    def _find_javac(self) -> str:
        oracle_java = r"C:\Program Files\Common Files\Oracle\Java\javapath\javac.exe"
        if os.path.exists(oracle_java):
            return oracle_java
        found = shutil.which("javac")
        if found:
            return found
        return "javac"

    def _parse_diagnostics(self, raw_stderr: str) -> Tuple[List[SyntaxErrorItem], List[SyntaxErrorItem]]:
        errors = []
        warnings = []
        pattern = re.compile(r":(\d+):\s*(error|warning):\s*(.*)")
        lines = raw_stderr.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i]
            match = pattern.search(line)
            if match:
                line_no = int(match.group(1))
                level = match.group(2).lower()
                msg = match.group(3).strip()
                col_no = 1

                # Lookahead for caret '^' indicator on subsequent lines
                if i + 2 < len(lines) and "^" in lines[i + 2]:
                    col_no = lines[i + 2].find("^") + 1

                err_type, explanation = categorize_java_diagnostic(msg)

                item = SyntaxErrorItem(
                    line=line_no,
                    column=col_no,
                    message=msg,
                    severity="error" if level == "error" else "warning",
                    source="javac",
                    error_type=err_type,
                    explanation=explanation,
                    original_message=line.strip()
                )
                if level == "error":
                    errors.append(item)
                else:
                    warnings.append(item)
            i += 1

        return errors, warnings

    def validate_syntax(self, code: str, file_name: Optional[str] = None) -> SyntaxValidationResult:
        # Extract class name if present (prioritize public class, then any class/record/interface/enum)
        class_match = re.search(r"public\s+class\s+([a-zA-Z0-9_]+)", code)
        if not class_match:
            class_match = re.search(r"(?:public\s+|final\s+|abstract\s+)?(?:class|record|interface|enum)\s+([a-zA-Z0-9_]+)", code)
        if class_match:
            class_name = class_match.group(1)
        elif file_name:
            base = os.path.splitext(os.path.basename(file_name))[0]
            class_name = base if re.match(r"^[a-zA-Z0-9_]+$", base) else "TempClass"
        else:
            class_name = "TempClass"

        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, f"{class_name}.java")

        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(code)

        try:
            cmd = [
                self.javac_path,
                "-proc:none",
                "-nowarn",
                temp_file_path
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

            if res.returncode != 0 and not errors:
                errors.append(SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=res.stderr.strip() or "Java compilation error",
                    severity="error",
                    source="javac",
                    error_type="CompilationError",
                    explanation="Java compiler reported a compilation error.",
                    original_message=res.stderr.strip()
                ))

            return SyntaxValidationResult(
                is_valid=len(errors) == 0 and res.returncode == 0,
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
                    message=f"Java compilation timed out after {COMPILER_TIMEOUT} seconds.",
                    severity="error",
                    source="javac",
                    error_type="CompilerTimeout",
                    explanation="javac took too long to validate syntax.",
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
                    message=f"Java validator error: {str(e)}",
                    severity="error",
                    source="javac",
                    error_type="InternalError",
                    explanation=str(e),
                    original_message=str(e)
                )],
                warnings=[],
                raw_output=str(e)
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None, already_validated: bool = False) -> LLVMIRResult:
        if not already_validated:
            syntax_res = self.validate_syntax(code, file_name)
            if not syntax_res.is_valid:
                error_msgs = "; ".join([f"Line {e.line}: {e.message}" for e in syntax_res.errors])
                return LLVMIRResult(
                    success=False,
                    ir_code="",
                    error=f"Java syntax validation failed: {error_msgs}"
                )

        class_match = re.search(r"class\s+([a-zA-Z0-9_]+)", code)
        class_name = class_match.group(1) if class_match else "JavaClass"

        methods = re.findall(r"(?:public|private|protected|static|\s)+[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*\{", code)

        ir_lines = [
            f"; ModuleID = 'java_{class_name}'",
            f"source_filename = \"{class_name}.java\"",
            "target datalayout = \"e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128\"",
            "target triple = \"x86_64-pc-windows-msvc\"",
            "",
            f"; --- Java Semantic Class Representation: {class_name} ---"
        ]

        for method in methods:
            ir_lines.append(f"\ndefine void @{class_name}_{method}(ptr %this) {{")
            ir_lines.append(f"entry_{method}:")
            ir_lines.append(f"  ; Java Method {method}")
            ir_lines.append(f"  %this.addr = alloca ptr, align 8")
            ir_lines.append(f"  store ptr %this, ptr %this.addr, align 8")
            ir_lines.append("  ret void")
            ir_lines.append("}")

        ir_content = "\n".join(ir_lines)
        return LLVMIRResult(
            success=True,
            ir_code=ir_content,
            metadata={"class_name": class_name, "methods": methods, "target_language": "Java"}
        )
