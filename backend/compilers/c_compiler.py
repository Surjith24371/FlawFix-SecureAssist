import os
import re
import shutil
import tempfile
import subprocess
from typing import Optional, List, Tuple
from backend.compilers.base_compiler import BaseCompiler
from backend.models.schema import SyntaxValidationResult, SyntaxErrorItem, LLVMIRResult

COMPILER_TIMEOUT = int(os.environ.get("FLAWFIX_COMPILER_TIMEOUT", "25"))

def categorize_clang_diagnostic(msg: str) -> Tuple[str, str]:
    """
    Classifies raw Clang diagnostic messages into structured categories and human-friendly explanations.
    """
    msg_l = msg.lower()
    if "expected ';'" in msg_l or "missing ';'" in msg_l:
        return "MissingSemicolon", "A semicolon ';' is required at the end of the statement or declaration."
    if "expected '}'" in msg_l or "expected closing '}'" in msg_l:
        return "UnclosedBrace", "Missing closing brace '}' to terminate block or function definition."
    if "expected ')'" in msg_l:
        return "UnclosedParenthesis", "Missing closing parenthesis ')' in expression or parameter list."
    if "expected ']'" in msg_l:
        return "UnclosedBracket", "Missing closing bracket ']' in array subscript or declaration."
    if "use of undeclared identifier" in msg_l or "undeclared variable" in msg_l:
        ident_match = re.search(r"'([^']+)'", msg)
        ident = f"'{ident_match.group(1)}'" if ident_match else "identifier"
        return "UndeclaredIdentifier", f"The identifier {ident} is referenced without being declared in this scope."
    if "incompatible type" in msg_l or "cannot initialize" in msg_l or "assigning to" in msg_l:
        return "TypeMismatch", "Type mismatch in variable assignment, return value, or function argument."
    if "unknown type name" in msg_l:
        type_match = re.search(r"'([^']+)'", msg)
        tname = f"'{type_match.group(1)}'" if type_match else "type"
        return "UnknownTypeName", f"The type {tname} is not recognized. Check header includes or typedefs."
    if "file not found" in msg_l:
        return "MissingHeader", "Included header file could not be found by the compiler."
    if "too few arguments" in msg_l or "too many arguments" in msg_l:
        return "InvalidFunctionCall", "Function call arguments do not match the function prototype."
    if "conflicting types" in msg_l or "redefinition of" in msg_l:
        return "ConflictingDeclaration", "Symbol is redeclared or redefined with conflicting types."
    if "expected expression" in msg_l:
        return "SyntaxError", "An expression was expected at this position."
    if "expected identifier" in msg_l:
        return "SyntaxError", "An identifier (variable or function name) was expected here."
    return "SyntaxError", msg

class CCompiler(BaseCompiler):
    """
    Compiler and Syntax Validator for C and C++ source code using Clang.
    Optimized for modern standards (C11/C++17), comment safety, and clean timeout handling.
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

    def _parse_diagnostics(self, raw_stderr: str) -> Tuple[List[SyntaxErrorItem], List[SyntaxErrorItem]]:
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
                err_type, explanation = categorize_clang_diagnostic(message)

                item = SyntaxErrorItem(
                    line=line_num,
                    column=col_num,
                    message=message,
                    severity="error" if "error" in diag_type else "warning",
                    source="clang",
                    error_type=err_type,
                    explanation=explanation,
                    original_message=line.strip()
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
                "-std=c++17" if self.is_cpp else "-std=c11",
                "-Wno-comment",
                "-fno-spell-checking",
                "-Qunused-arguments",
                "-Wall",
                temp_path
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMPILER_TIMEOUT
            )
            
            raw_output = res.stderr or res.stdout
            errors, warnings = self._parse_diagnostics(raw_output)

            # If returncode is non-zero and no errors were parsed by regex, add general error
            if res.returncode != 0 and not errors:
                errors.append(SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=raw_output.strip() or "Compilation failed",
                    severity="error",
                    source="clang",
                    error_type="CompilationError",
                    explanation="Clang encountered a compilation error.",
                    original_message=raw_output.strip()
                ))

            is_valid = len(errors) == 0 and res.returncode == 0
            return SyntaxValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                raw_output=raw_output
            )
        except subprocess.TimeoutExpired:
            return SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Syntax validation timed out after {COMPILER_TIMEOUT} seconds.",
                    severity="error",
                    source="clang",
                    error_type="CompilerTimeout",
                    explanation="The compiler took too long to validate syntax.",
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
                    message=f"Validator execution error: {str(e)}",
                    severity="error",
                    source="clang",
                    error_type="InternalError",
                    explanation=str(e),
                    original_message=str(e)
                )],
                warnings=[],
                raw_output=str(e)
            )
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None, already_validated: bool = False) -> LLVMIRResult:
        # If not already validated, run syntax check first
        if not already_validated:
            syntax_res = self.validate_syntax(code, file_name)
            if not syntax_res.is_valid:
                for e in syntax_res.errors:
                    if e.error_type == "CompilerTimeout" or "timed out" in e.message.lower():
                        return LLVMIRResult(
                            success=False,
                            ir_code="",
                            error="LLVM IR generation timed out while processing the source code. Security analysis could not be completed."
                        )
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
                "-gline-tables-only",
                "-fno-color-diagnostics",
                "-fno-spell-checking",
                "-Qunused-arguments",
                "-std=c++17" if self.is_cpp else "-std=c11",
                "-Wno-comment",
                "-Xclang",
                "-disable-O0-optnone",
                temp_path,
                "-o",
                temp_ll_path
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
                    error=f"Clang LLVM IR generation failed: {res.stderr.strip() or res.stdout.strip()}"
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
                error=f"Compiler exception: {str(e)}"
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
        Executes an optimized single-pass compilation pipeline using Clang.
        Validates syntax and produces LLVM IR in a single compiler invocation, avoiding redundant parsing.
        """
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
                "-gline-tables-only",
                "-fno-color-diagnostics",
                "-fno-spell-checking",
                "-Qunused-arguments",
                "-std=c++17" if self.is_cpp else "-std=c11",
                "-Wno-comment",
                "-Wall",
                "-Xclang",
                "-disable-O0-optnone",
                temp_path,
                "-o",
                temp_ll_path
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMPILER_TIMEOUT
            )

            raw_output = res.stderr or res.stdout
            errors, warnings = self._parse_diagnostics(raw_output)

            # If returncode is non-zero, syntax/compilation failed
            if res.returncode != 0:
                if not errors:
                    errors.append(SyntaxErrorItem(
                        line=1,
                        column=1,
                        message=raw_output.strip() or "Compilation failed",
                        severity="error",
                        source="clang",
                        error_type="CompilationError",
                        explanation="Clang encountered a compilation error.",
                        original_message=raw_output.strip()
                    ))
                syntax_res = SyntaxValidationResult(
                    is_valid=False,
                    errors=errors,
                    warnings=warnings,
                    raw_output=raw_output
                )
                return syntax_res, None

            # returncode == 0: syntax is valid, read generated LLVM IR
            syntax_res = SyntaxValidationResult(
                is_valid=True,
                errors=[],
                warnings=warnings,
                raw_output=raw_output
            )

            if os.path.exists(temp_ll_path):
                with open(temp_ll_path, "r", encoding="utf-8", errors="replace") as f:
                    ir_content = f.read()

                functions = re.findall(r"define\s+[^@]*@([a-zA-Z0-9_]+)\s*\(", ir_content)
                metadata = {
                    "functions": functions,
                    "function_count": len(functions),
                    "ir_line_count": len(ir_content.splitlines()),
                    "target_language": "C++" if self.is_cpp else "C"
                }
                ir_res = LLVMIRResult(
                    success=True,
                    ir_code=ir_content,
                    ir_file_path=temp_ll_path,
                    metadata=metadata
                )
                return syntax_res, ir_res
            else:
                ir_res = LLVMIRResult(
                    success=False,
                    ir_code="",
                    error="LLVM IR file was not generated by Clang."
                )
                return syntax_res, ir_res

        except subprocess.TimeoutExpired:
            syntax_res = SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Syntax validation timed out after {COMPILER_TIMEOUT} seconds.",
                    severity="error",
                    source="clang",
                    error_type="CompilerTimeout",
                    explanation="The compiler took too long to validate syntax.",
                    original_message="subprocess.TimeoutExpired"
                )],
                warnings=[],
                raw_output="TimeoutExpired"
            )
            return syntax_res, None
        except Exception as e:
            syntax_res = SyntaxValidationResult(
                is_valid=False,
                errors=[SyntaxErrorItem(
                    line=1,
                    column=1,
                    message=f"Validator execution error: {str(e)}",
                    severity="error",
                    source="clang",
                    error_type="InternalError",
                    explanation=str(e),
                    original_message=str(e)
                )],
                warnings=[],
                raw_output=str(e)
            )
            return syntax_res, None
        finally:
            for p in [temp_path, temp_ll_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
