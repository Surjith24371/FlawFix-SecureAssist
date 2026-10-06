import re
import ast
import textwrap
from typing import Optional, Tuple, List

class FunctionPatchReplacer:
    """
    Grammar- and brace-depth-aware function boundary locator and replacer for C, C++, Rust, Java, and Python.
    Replaces a vulnerable function with a secure patch while strictly preserving:
    - Preceding and trailing comments
    - Indentation
    - Surrounding functions, macros, and global variables
    - Nested braces (if, while, for, switch, compound blocks)
    - Rust lifetimes ('static, 'a) without corrupting character literal scanning
    """

    @staticmethod
    def sanitize_func_name(func_name: Optional[str]) -> str:
        """
        Cleans any function signature or qualified name down to the raw function identifier.
        Examples:
        - 'void vulnerable_func(char *str)' -> 'vulnerable_func'
        - 'DataHandler::process_data' -> 'process_data'
        - 'VulnerableClass.vulnerableFunc' -> 'vulnerableFunc'
        - 'pub fn process_input(input: &[u8])' -> 'process_input'
        - 'vulnerable_func()' -> 'vulnerable_func'
        """
        if not func_name:
            return ""
        # Strip parameters/signature: "void foo(int x)" -> "void foo"
        clean = func_name.split("(")[0].strip()
        # Strip namespace/class qualifiers: "MyClass::foo" -> "foo", "MyClass.foo" -> "foo"
        if "::" in clean:
            clean = clean.split("::")[-1].strip()
        if "." in clean:
            clean = clean.split(".")[-1].strip()
        # Take last word if qualifiers/return types present: "pub fn foo" -> "foo", "void foo" -> "foo"
        parts = clean.split()
        if parts:
            clean = parts[-1].strip()
        # Strip leading pointer/reference chars
        clean = clean.lstrip("*&")
        return clean

    @classmethod
    def extract_function_name_from_patch(cls, patch_code: str, language: str) -> Optional[str]:
        clean = patch_code.strip()
        lang_norm = (language or "").lower().strip()

        # 1. Python: def name(
        if lang_norm in ("python", "py"):
            match = re.search(r"^[ \t]*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", clean, re.MULTILINE)
            if match:
                return match.group(1)
            return None

        # 2. Rust: fn name< or fn name(
        if lang_norm in ("rust", "rs"):
            match = re.search(r"\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[<(]", clean)
            if match:
                return match.group(1)
            return None

        # 3. C, C++, Java: [qualifiers/types] name(params) [throws/const/noexcept/etc] {
        no_comments = re.sub(r"/\*[\s\S]*?\*/|//.*$", "", clean, flags=re.MULTILINE)
        keywords = {"if", "while", "for", "switch", "catch", "return", "sizeof", "typeof", "alignof", "struct", "class", "enum", "union"}
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;{()]*\)[^{;]*\{", no_comments):
            fn = m.group(1).strip()
            if fn not in keywords:
                return fn

        return None

    @classmethod
    def find_python_function_bounds(cls, source: str, func_name: str) -> Optional[Tuple[int, int]]:
        """
        Locates the exact start and end char indices of a Python function using AST or indentation.
        """
        raw_name = cls.sanitize_func_name(func_name)
        if not raw_name:
            return None

        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == raw_name:
                    lines = source.splitlines(keepends=True)
                    start_line_1 = node.lineno
                    if node.decorator_list:
                        start_line_1 = node.decorator_list[0].lineno
                    end_line_1 = getattr(node, 'end_lineno', None)

                    if end_line_1 is None:
                        base_indent = node.col_offset
                        idx = start_line_1
                        while idx < len(lines):
                            curr_line = lines[idx]
                            if curr_line.strip() and not curr_line.lstrip().startswith("#"):
                                curr_indent = len(curr_line) - len(curr_line.lstrip())
                                if curr_indent <= base_indent:
                                    break
                            idx += 1
                        end_line_1 = idx

                    start_char = sum(len(lines[i]) for i in range(start_line_1 - 1))
                    end_char = sum(len(lines[i]) for i in range(end_line_1))
                    return start_char, end_char
        except Exception:
            pass

        # Fallback: regex search on def
        pattern = re.compile(r"^([ \t]*)def\s+" + re.escape(raw_name) + r"\b", re.MULTILINE)
        m = pattern.search(source)
        if not m:
            return None
        start_char = m.start()
        indent_len = len(m.group(1))

        lines = source[m.end():].splitlines(keepends=True)
        consumed = m.end()
        for line in lines:
            if line.strip() and not line.lstrip().startswith("#"):
                curr_indent = len(line) - len(line.lstrip())
                if curr_indent <= indent_len:
                    break
            consumed += len(line)
        return start_char, consumed

    @classmethod
    def find_brace_function_bounds(cls, source: str, func_name: str) -> Optional[Tuple[int, int]]:
        """
        Locates the exact start and end char indices of a C/C++/Java/Rust function.
        Uses tokenizer tracking to skip strings, single-line comments, multiline comments,
        and Rust lifetimes.
        Accurately tracks nested braces so it NEVER stops prematurely on inner blocks.
        """
        raw_name = cls.sanitize_func_name(func_name)
        if not raw_name:
            return None

        # Match word boundary followed by raw_name and either '(' or '<' (for generic functions in Rust/C++)
        sig_pattern = re.compile(r"\b" + re.escape(raw_name) + r"\s*[<(]")

        for m in sig_pattern.finditer(source):
            func_name_idx = m.start()

            # Verify func_name_idx is not inside a comment or string
            if cls._is_inside_comment_or_string(source, func_name_idx):
                continue

            # Scan backwards to find the start of the function definition line
            line_start = source.rfind("\n", 0, func_name_idx)
            start_char = 0 if line_start == -1 else line_start + 1

            # Walk backwards over preceding lines if qualifiers/attributes/annotations are on previous lines
            cur_pos = start_char
            while cur_pos > 0:
                prev_nl = source.rfind("\n", 0, cur_pos - 1)
                prev_line_start = 0 if prev_nl == -1 else prev_nl + 1
                prev_line = source[prev_line_start:cur_pos].strip()
                if not prev_line or prev_line.endswith(";") or prev_line.endswith("}") or prev_line.endswith(":") or prev_line.startswith("//") or prev_line.startswith("/*") or prev_line.startswith("#include") or prev_line in ("public:", "private:", "protected:"):
                    break
                # Allow return types, qualifiers, decorators, attributes (@Override, #[inline], [[nodiscard]], pub, static)
                if re.match(r"^[@a-zA-Z0-9_*&<>:()\[\]\s]+$", prev_line):
                    start_char = prev_line_start
                    cur_pos = prev_line_start
                else:
                    break

            # Scan forward from function name to find the opening brace '{'
            open_brace_idx = cls._find_opening_brace(source, m.end() - 1)
            if open_brace_idx is None:
                continue

            # Track nested braces counting depth until 0
            close_brace_idx = cls._find_matching_closing_brace(source, open_brace_idx)
            if close_brace_idx is not None:
                end_char = close_brace_idx + 1
                if end_char < len(source) and source[end_char] == "\n":
                    end_char += 1
                elif end_char + 1 < len(source) and source[end_char:end_char+2] == "\r\n":
                    end_char += 2
                return start_char, end_char

        return None

    @classmethod
    def find_brace_class_bounds(cls, source: str, class_name: str) -> Optional[Tuple[int, int]]:
        """
        Locates the exact start and end char indices of a class, struct, record, or interface in C++, Java, Rust, or C.
        Handles qualifiers (public, final, abstract, static), annotations, inheritance, and implements clauses.
        """
        raw_name = cls.sanitize_func_name(class_name)
        if not raw_name:
            return None

        pattern = re.compile(r"\b(?:class|struct|record|interface|enum)\s+" + re.escape(raw_name) + r"\b")
        for m in pattern.finditer(source):
            class_kw_idx = m.start()
            if cls._is_inside_comment_or_string(source, class_kw_idx):
                continue

            # Scan backwards to include preceding annotations/qualifiers on previous lines
            line_start = source.rfind("\n", 0, class_kw_idx)
            start_char = 0 if line_start == -1 else line_start + 1

            cur_pos = start_char
            while cur_pos > 0:
                prev_nl = source.rfind("\n", 0, cur_pos - 1)
                prev_line_start = 0 if prev_nl == -1 else prev_nl + 1
                prev_line = source[prev_line_start:cur_pos].strip()
                if not prev_line or prev_line.endswith(";") or prev_line.endswith("}") or prev_line.startswith("//") or prev_line.startswith("/*") or prev_line.startswith("package") or prev_line.startswith("import"):
                    break
                if re.match(r"^[@a-zA-Z0-9_*&<>:()\[\]\s]+$", prev_line):
                    start_char = prev_line_start
                    cur_pos = prev_line_start
                else:
                    break

            open_brace_idx = cls._find_opening_brace(source, m.end())
            if open_brace_idx is None:
                continue

            close_brace_idx = cls._find_matching_closing_brace(source, open_brace_idx)
            if close_brace_idx is not None:
                end_char = close_brace_idx + 1
                if end_char < len(source) and source[end_char] == ";":
                    end_char += 1
                if end_char < len(source) and source[end_char] == "\n":
                    end_char += 1
                elif end_char + 1 < len(source) and source[end_char:end_char+2] == "\r\n":
                    end_char += 2
                return start_char, end_char

        return None

    @classmethod
    def extract_methods_from_code(cls, code: str, lang_norm: str) -> List[str]:
        """
        Extracts all function or method names declared in the given source snippet.
        """
        methods = []
        if lang_norm in ("python", "py"):
            for m in re.finditer(r"^[ \t]*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", code, re.MULTILINE):
                fn = m.group(1)
                if fn not in methods:
                    methods.append(fn)
            return methods

        no_comments = re.sub(r"/\*[\s\S]*?\*/|//.*$", "", code, flags=re.MULTILINE)
        keywords = {"if", "while", "for", "switch", "catch", "return", "sizeof", "typeof", "alignof", "struct", "class", "enum", "union", "new", "delete", "throw"}
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;{()]*\)[^{;]*\{", no_comments):
            fn = m.group(1).strip()
            if fn not in keywords and fn not in methods:
                methods.append(fn)
        return methods

    @staticmethod
    def _is_inside_comment_or_string(source: str, target_idx: int) -> bool:
        i = 0
        n = len(source)
        while i < target_idx:
            c = source[i]
            # Single-line comment
            if c == '/' and i + 1 < n and source[i + 1] == '/':
                nl = source.find("\n", i)
                if nl == -1 or nl > target_idx:
                    return True
                i = nl + 1
                continue
            # Multi-line comment
            if c == '/' and i + 1 < n and source[i + 1] == '*':
                close = source.find("*/", i + 2)
                if close == -1 or close + 2 > target_idx:
                    return True
                i = close + 2
                continue
            # String literals
            if c == '"':
                i += 1
                while i < n and source[i] != '"':
                    if source[i] == '\\':
                        i += 1
                    i += 1
                if i >= target_idx:
                    return True
                i += 1
                continue
            # Chars & lifetimes (do not treat Rust lifetimes as open quotes)
            if c == "'":
                nl = source.find("\n", i)
                close_quote = source.find("'", i + 1)
                if close_quote != -1 and (nl == -1 or close_quote < nl) and (close_quote - i) <= 6:
                    if close_quote >= target_idx:
                        return True
                    i = close_quote + 1
                    continue
                else:
                    i += 1
                    continue
            i += 1
        return False

    @staticmethod
    def _find_opening_brace(source: str, from_idx: int) -> Optional[int]:
        i = from_idx
        n = len(source)
        paren_depth = 0
        bracket_depth = 0
        while i < n:
            c = source[i]
            if c == '/' and i + 1 < n and source[i + 1] == '/':
                nl = source.find("\n", i)
                i = n if nl == -1 else nl + 1
                continue
            if c == '/' and i + 1 < n and source[i + 1] == '*':
                close = source.find("*/", i + 2)
                i = n if close == -1 else close + 2
                continue
            if c == '"':
                i += 1
                while i < n and source[i] != '"':
                    if source[i] == '\\':
                        i += 1
                    i += 1
                i += 1
                continue
            if c == "'":
                nl = source.find("\n", i)
                close_quote = source.find("'", i + 1)
                if close_quote != -1 and (nl == -1 or close_quote < nl) and (close_quote - i) <= 6:
                    i = close_quote + 1
                    continue
                else:
                    i += 1
                    continue
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth = max(0, paren_depth - 1)
            elif c == '[':
                bracket_depth += 1
            elif c == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif c == '{' and paren_depth == 0 and bracket_depth == 0:
                return i
            elif c == ';' and paren_depth == 0 and bracket_depth == 0:
                return None
            i += 1
        return None

    @staticmethod
    def _find_matching_closing_brace(source: str, open_brace_idx: int) -> Optional[int]:
        i = open_brace_idx + 1
        n = len(source)
        brace_depth = 1
        while i < n:
            c = source[i]
            if c == '/' and i + 1 < n and source[i + 1] == '/':
                nl = source.find("\n", i)
                i = n if nl == -1 else nl + 1
                continue
            if c == '/' and i + 1 < n and source[i + 1] == '*':
                close = source.find("*/", i + 2)
                i = n if close == -1 else close + 2
                continue
            if c == '"':
                i += 1
                while i < n and source[i] != '"':
                    if source[i] == '\\':
                        i += 1
                    i += 1
                i += 1
                continue
            if c == "'":
                nl = source.find("\n", i)
                close_quote = source.find("'", i + 1)
                if close_quote != -1 and (nl == -1 or close_quote < nl) and (close_quote - i) <= 6:
                    i = close_quote + 1
                    continue
                else:
                    i += 1
                    continue
            if c == '{':
                brace_depth += 1
            elif c == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    return i
            i += 1
        return None

    @staticmethod
    def extract_top_directives(patch_code: str, lang_norm: str) -> Tuple[List[str], str]:
        """
        Extracts preprocessor directives, imports, or use statements from a patch,
        returning the extracted directives and the clean function body.
        """
        directives = []
        body_lines = []
        for line in patch_code.splitlines():
            stripped = line.strip()
            if lang_norm in ("c", "cpp") and re.match(r"^\s*#\s*include\s*[<\"][^>\"]+[>\"]", line):
                directives.append(stripped)
            elif lang_norm in ("python", "py") and re.match(r"^\s*(?:import\s+[a-zA-Z0-9_.]+|from\s+[a-zA-Z0-9_.]+\s+import\s+)", line):
                directives.append(stripped)
            elif lang_norm == "rust" and re.match(r"^\s*use\s+[^;]+;", line):
                directives.append(stripped)
            elif lang_norm == "java" and re.match(r"^\s*import\s+[a-zA-Z0-9_.*]+;", line):
                directives.append(stripped)
            else:
                body_lines.append(line)
        return directives, "\n".join(body_lines).strip()

    @staticmethod
    def inject_missing_headers_and_imports(code: str, lang_norm: str) -> str:
        """
        Guarantees that essential standard headers or imports are present in the final source
        if standard library functions or types are referenced.
        """
        merged = code
        if lang_norm in ("c", "cpp"):
            # String functions
            str_funcs = ["strlen", "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memset", "memmove", "strcmp", "strncmp"]
            if any(re.search(rf"\b{fn}\b", merged) for fn in str_funcs):
                if "#include <string.h>" not in merged and "#include <cstring>" not in merged:
                    merged = "#include <string.h>\n" + merged

            # Standard I/O
            io_funcs = ["snprintf", "printf", "fprintf", "sprintf", "puts", "fopen", "fclose", "FILE"]
            if any(re.search(rf"\b{fn}\b", merged) for fn in io_funcs):
                if "#include <stdio.h>" not in merged and "#include <cstdio>" not in merged:
                    merged = "#include <stdio.h>\n" + merged

            # Standard library / Memory
            stdlib_symbols = ["malloc", "free", "calloc", "realloc", "NULL", "exit", "atoi", "strtol"]
            if any(re.search(rf"\b{s}\b", merged) for s in stdlib_symbols):
                if "#include <stdlib.h>" not in merged and "#include <cstdlib>" not in merged:
                    merged = "#include <stdlib.h>\n" + merged

            # Fixed-width integers
            int_types = ["uint8_t", "int8_t", "uint16_t", "int16_t", "uint32_t", "int32_t", "uint64_t", "int64_t"]
            if any(re.search(rf"\b{t}\b", merged) for t in int_types):
                if "#include <stdint.h>" not in merged and "#include <cstdint>" not in merged:
                    merged = "#include <stdint.h>\n" + merged

            # Standard definitions
            if re.search(r"\bsize_t\b", merged) or re.search(r"\bptrdiff_t\b", merged):
                if "#include <stddef.h>" not in merged and "#include <cstddef>" not in merged and "#include <stdint.h>" not in merged:
                    merged = "#include <stddef.h>\n" + merged

            # Booleans for C
            if lang_norm == "c" and any(re.search(rf"\b{b}\b", merged) for b in ["bool", "true", "false"]):
                if "#include <stdbool.h>" not in merged:
                    merged = "#include <stdbool.h>\n" + merged

            # Numeric limits
            if any(re.search(rf"\b{l}\b", merged) for l in ["INT_MAX", "INT_MIN", "UINT_MAX", "LONG_MAX"]):
                if "#include <limits.h>" not in merged and "#include <climits>" not in merged:
                    merged = "#include <limits.h>\n" + merged

            # C++ specific standard headers
            if lang_norm == "cpp":
                if ("std::min" in merged or "std::max" in merged or "std::clamp" in merged or "std::sort" in merged) and "#include <algorithm>" not in merged:
                    merged = "#include <algorithm>\n" + merged
                if "std::string" in merged and "#include <string>" not in merged:
                    merged = "#include <string>\n" + merged
                if "std::vector" in merged and "#include <vector>" not in merged:
                    merged = "#include <vector>\n" + merged
                if ("std::cout" in merged or "std::cin" in merged or "std::endl" in merged) and "#include <iostream>" not in merged:
                    merged = "#include <iostream>\n" + merged

        elif lang_norm in ("python", "py"):
            py_modules = [
                ("sqlite3", "import sqlite3"),
                ("hashlib", "import hashlib"),
                ("hmac", "import hmac"),
                ("secrets", "import secrets"),
                ("re.", "import re"),
                ("os.path", "import os")
            ]
            for trigger, imp in py_modules:
                if trigger in merged and imp not in merged:
                    merged = imp + "\n" + merged

        elif lang_norm == "java":
            java_imports = [
                (["PreparedStatement", "Connection", "SQLException", "ResultSet"], "import java.sql.*;"),
                (["Pattern", "Matcher"], "import java.util.regex.*;"),
                (["List", "ArrayList", "Map", "HashMap", "Set", "HashSet"], "import java.util.*;")
            ]
            for symbols, imp in java_imports:
                if any(re.search(rf"\b{s}\b", merged) for s in symbols) and imp not in merged:
                    pkg_match = re.search(r"^\s*package\s+[^;]+;\s*\n", merged)
                    if pkg_match:
                        insert_pos = pkg_match.end()
                        merged = merged[:insert_pos] + imp + "\n" + merged[insert_pos:]
                    else:
                        merged = imp + "\n" + merged

        return merged

    @classmethod
    def apply_patch(cls, original_code: str, patch_code: str, function_name: Optional[str] = None, language: str = "c") -> str:
        clean_patch = textwrap.dedent(patch_code).strip()
        lang_norm = (language or "c").lower().strip()

        # Step 0: Extract directives from patch so they don't get embedded inside function bodies
        directives, func_patch = cls.extract_top_directives(clean_patch, lang_norm)
        patch_to_splice = func_patch if func_patch else clean_patch

        # Step 1: Resolve target function name
        target_func = cls.sanitize_func_name(function_name)
        if not target_func:
            target_func = cls.extract_function_name_from_patch(patch_to_splice, lang_norm)

        # Step 1.5: Prevent duplicate class definitions (e.g. Java 'class FileReaderApp')
        # Check if patch_to_splice contains an enclosing class/struct/record
        class_pattern = re.compile(r"\b(?:class|struct|record|interface)\s+([a-zA-Z_][a-zA-Z0-9_]*)")
        patch_class_match = class_pattern.search(patch_to_splice)

        bounds = None
        if patch_class_match:
            patch_class = patch_class_match.group(1)
            orig_class_bounds = cls.find_brace_class_bounds(original_code, patch_class)

            if orig_class_bounds:
                # Both original code and patch declare the same class!
                orig_methods = cls.extract_methods_from_code(original_code, lang_norm)
                patch_methods = cls.extract_methods_from_code(patch_to_splice, lang_norm)

                if not target_func or target_func == patch_class:
                    if patch_methods:
                        target_func = patch_methods[0]

                # Check if patch is a full class replacement vs single repaired method wrapped in class
                other_orig_methods = set(orig_methods) - ({target_func} if target_func else set())
                has_other_methods_in_patch = bool(other_orig_methods.intersection(set(patch_methods)))

                if has_other_methods_in_patch or target_func == patch_class:
                    # Full class replacement: replace the entire class bounds in original_code
                    bounds = orig_class_bounds
                else:
                    # Method-level repair wrapped inside class: unwrap class body to splice into method bounds
                    if target_func:
                        if lang_norm in ("python", "py"):
                            bounds = cls.find_python_function_bounds(original_code, target_func)
                        else:
                            bounds = cls.find_brace_function_bounds(original_code, target_func)

                    if bounds:
                        open_b = cls._find_opening_brace(patch_to_splice, patch_class_match.end())
                        if open_b is not None:
                            close_b = cls._find_matching_closing_brace(patch_to_splice, open_b)
                            if close_b is not None:
                                unwrapped_body = textwrap.dedent(patch_to_splice[open_b + 1:close_b]).strip()
                                if unwrapped_body:
                                    patch_to_splice = unwrapped_body
                    else:
                        # Fallback: if specific method bounds in original_code not located, replace class
                        bounds = orig_class_bounds

        # Step 2: Locate function bounds in original code if not already found
        if not bounds and target_func:
            if lang_norm in ("python", "py"):
                bounds = cls.find_python_function_bounds(original_code, target_func)
            else:
                bounds = cls.find_brace_function_bounds(original_code, target_func)

        # Step 3: If target_func not found, try extracting identifier from patch directly
        if not bounds:
            patch_fn = cls.extract_function_name_from_patch(patch_to_splice, lang_norm)
            if patch_fn and patch_fn != target_func:
                if lang_norm in ("python", "py"):
                    bounds = cls.find_python_function_bounds(original_code, patch_fn)
                else:
                    bounds = cls.find_brace_function_bounds(original_code, patch_fn)

        if bounds:
            start_idx, end_idx = bounds

            # Detect indentation of original function opening line
            orig_line_start = original_code.rfind("\n", 0, start_idx)
            orig_line_start = 0 if orig_line_start == -1 else orig_line_start + 1
            indent_match = re.match(r"^([ \t]*)", original_code[start_idx:end_idx])
            if not indent_match or not indent_match.group(1):
                indent_match = re.match(r"^([ \t]*)", original_code[orig_line_start:start_idx])
            leading_indent = indent_match.group(1) if indent_match else ""

            # Ensure proper indentation (dedenting first for Python prevents IndentationError)
            formatted_patch = patch_to_splice
            if lang_norm in ("python", "py"):
                formatted_patch = textwrap.dedent(patch_to_splice)

            if leading_indent:
                patch_lines = formatted_patch.splitlines()
                formatted_patch = "\n".join(
                    (leading_indent + line if line.strip() else line)
                    for line in patch_lines
                )

            merged = original_code[:start_idx] + formatted_patch + "\n" + original_code[end_idx:]

            # Prepend any extracted directives not already present in merged
            for d in reversed(directives):
                if d not in merged:
                    merged = d + "\n" + merged

            # Ensure all referenced standard headers and imports exist
            return cls.inject_missing_headers_and_imports(merged, lang_norm)

        # If patch appears to be full source or script, dedent for Python, merge directives, and ensure headers
        merged = textwrap.dedent(clean_patch) if lang_norm in ("python", "py") else clean_patch
        for d in reversed(directives):
            if d not in merged:
                merged = d + "\n" + merged

        return cls.inject_missing_headers_and_imports(merged, lang_norm)
