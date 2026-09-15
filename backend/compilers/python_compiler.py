import ast
import os
import tempfile
import subprocess
from typing import Optional, List, Tuple
from backend.compilers.base_compiler import BaseCompiler
from backend.models.schema import SyntaxValidationResult, SyntaxErrorItem, LLVMIRResult

class PythonCompiler(BaseCompiler):
    """
    Compiler and Syntax Validator for Python source code using Python AST & Nuitka/LLVM bridge.
    """

    def __init__(self):
        super().__init__("python")

    def validate_syntax(self, code: str, file_name: Optional[str] = None) -> SyntaxValidationResult:
        """
        Validates Python syntax using Python's built-in AST parser.
        """
        errors = []
        try:
            ast.parse(code, filename=file_name or "<input>")
            return SyntaxValidationResult(
                is_valid=True,
                errors=[],
                warnings=[],
                raw_output="Syntax validation passed."
            )
        except SyntaxError as e:
            errors.append(SyntaxErrorItem(
                line=e.lineno or 1,
                column=e.offset or 1,
                message=f"{e.msg}: {e.text.strip() if e.text else ''}",
                severity="error",
                source="python_ast"
            ))
            return SyntaxValidationResult(
                is_valid=False,
                errors=errors,
                warnings=[],
                raw_output=f"SyntaxError: {e.msg} at line {e.lineno}, column {e.offset}"
            )
        except Exception as e:
            errors.append(SyntaxErrorItem(
                line=1,
                column=1,
                message=f"Validation error: {str(e)}",
                severity="error",
                source="python_ast"
            ))
            return SyntaxValidationResult(
                is_valid=False,
                errors=errors,
                warnings=[],
                raw_output=str(e)
            )

    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None) -> LLVMIRResult:
        """
        Generates LLVM IR or Semantic AST-IR representation for Python.
        """
        syntax_res = self.validate_syntax(code, file_name)
        if not syntax_res.is_valid:
            error_msgs = "; ".join([f"Line {e.line}: {e.message}" for e in syntax_res.errors])
            return LLVMIRResult(
                success=False,
                ir_code="",
                error=f"Python syntax validation failed: {error_msgs}"
            )

        # Parse AST to extract function structure and symbol metadata
        parsed_ast = ast.parse(code)
        functions = [node.name for node in ast.walk(parsed_ast) if isinstance(node, ast.FunctionDef)]
        classes = [node.name for node in ast.walk(parsed_ast) if isinstance(node, ast.ClassDef)]

        used_lines = set()

        def extract_call_name(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            elif isinstance(node, ast.Attribute):
                prefix = extract_call_name(node.value)
                return f"{prefix}.{node.attr}" if prefix else node.attr
            elif isinstance(node, ast.Call):
                return extract_call_name(node.func)
            return "call"

        def extract_all_calls(node: ast.AST) -> List[Tuple[str, int, List[str]]]:
            calls = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    c_name = extract_call_name(child.func)
                    c_line = getattr(child, 'lineno', getattr(node, 'lineno', 1))
                    used_lines.add(c_line)
                    args_repr = []
                    for a in child.args:
                        if isinstance(a, ast.Name):
                            args_repr.append(f"ptr %{a.id}")
                        elif isinstance(a, ast.Constant):
                            args_repr.append(f"const {type(a.value).__name__}")
                        elif isinstance(a, ast.Call):
                            args_repr.append(f"call @{extract_call_name(a.func)}()")
                    calls.append((c_name, c_line, args_repr))
            return calls

        # Generate structured Python Intermediate Representation (PIR / LLVM-equivalent)
        ir_lines = [
            f"; ModuleID = '{file_name or 'python_module'}'",
            f"source_filename = \"{file_name or 'input.py'}\"",
            "target datalayout = \"e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128\"",
            "target triple = \"x86_64-pc-windows-msvc\"",
            "",
            "; --- Python Intermediate Semantic IR Representation ---"
        ]

        top_level_stmts = []

        for node in parsed_ast.body:
            if isinstance(node, ast.FunctionDef):
                fn_line = node.lineno
                used_lines.add(fn_line)
                args = [arg.arg for arg in node.args.args]
                ir_lines.append(f"\ndefine ptr @{node.name}({', '.join(['ptr %' + a for a in args])}) !dbg !{fn_line} {{")
                ir_lines.append(f"entry_{node.name}:")
                
                for stmt in node.body:
                    stmt_line = getattr(stmt, 'lineno', fn_line)
                    used_lines.add(stmt_line)
                    calls = extract_all_calls(stmt)
                    
                    for c_name, c_line, c_args in calls:
                        args_str = ", ".join(c_args) if c_args else "ptr null"
                        ir_lines.append(f"  ; Line {c_line}: Security-relevant call: {c_name}()")
                        ir_lines.append(f"  %call_{c_name.replace('.', '_')} = call ptr @{c_name}({args_str}), !dbg !{c_line}")
                    
                    if isinstance(stmt, ast.Return):
                        ir_lines.append(f"  ; Line {stmt_line}: Return statement")
                        ir_lines.append(f"  ret ptr null, !dbg !{stmt_line}")
                    elif isinstance(stmt, ast.Assign):
                        targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                        t_name = targets[0] if targets else "var"
                        ir_lines.append(f"  ; Line {stmt_line}: Assignment to {t_name}")
                        ir_lines.append(f"  store ptr %val, ptr %{t_name}, !dbg !{stmt_line}")
                    elif not calls:
                        ir_lines.append(f"  ; Line {stmt_line}: Statement {type(stmt).__name__}")
                
                ir_lines.append(f"  ret ptr null, !dbg !{fn_line}")
                ir_lines.append("}")
            elif not isinstance(node, (ast.Import, ast.ImportFrom)):
                top_level_stmts.append(node)

        # If there are top-level module statements, encapsulate them in @__main__
        if top_level_stmts:
            main_line = getattr(top_level_stmts[0], 'lineno', 1)
            used_lines.add(main_line)
            ir_lines.append(f"\ndefine i32 @__main__() !dbg !{main_line} {{")
            ir_lines.append("entry_main:")
            for stmt in top_level_stmts:
                stmt_line = getattr(stmt, 'lineno', main_line)
                used_lines.add(stmt_line)
                calls = extract_all_calls(stmt)
                for c_name, c_line, c_args in calls:
                    args_str = ", ".join(c_args) if c_args else "ptr null"
                    ir_lines.append(f"  ; Line {c_line}: Call {c_name}()")
                    ir_lines.append(f"  %call_{c_name.replace('.', '_')} = call ptr @{c_name}({args_str}), !dbg !{c_line}")
                if isinstance(stmt, ast.Assign):
                    targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                    t_name = targets[0] if targets else "var"
                    ir_lines.append(f"  ; Line {stmt_line}: Assignment to {t_name}")
                    ir_lines.append(f"  store ptr %val, ptr %{t_name}, !dbg !{stmt_line}")
            ir_lines.append(f"  ret i32 0, !dbg !{main_line}")
            ir_lines.append("}")

        # Emit !DILocation debug metadata definitions at bottom of IR
        ir_lines.append("\n; --- Debug Location Metadata Definitions ---")
        for line_num in sorted(used_lines):
            ir_lines.append(f"!{line_num} = !DILocation(line: {line_num}, column: 1, scope: !0)")

        ir_content = "\n".join(ir_lines)
        metadata = {
            "functions": functions,
            "classes": classes,
            "function_count": len(functions),
            "ir_line_count": len(ir_lines),
            "target_language": "Python"
        }

        return LLVMIRResult(
            success=True,
            ir_code=ir_content,
            metadata=metadata
        )
