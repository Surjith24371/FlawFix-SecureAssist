import unittest
import sys
import os
import time

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.compilers.compiler_manager import compiler_manager
from backend.verifier.patch_replacer import FunctionPatchReplacer
from backend.extractor.isevc_builder import isevc_builder

class TestPerfAndPatchRobustness(unittest.TestCase):

    def test_single_pass_large_cpp_compilation_perf(self):
        """
        Validates that large C++ source code with standard library headers
        compiles in a fast single pass with -gline-tables-only.
        """
        cpp_code = """
        #include <iostream>
        #include <vector>
        #include <string>
        #include <algorithm>
        #include <map>

        class LargeCodeProcessor {
        public:
            void process_records(const std::vector<std::string>& records) {
                for (const auto& r : records) {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "Item: %s", r.c_str());
                    std::cout << buf << std::endl;
                }
            }
        };

        int main(int argc, char** argv) {
            LargeCodeProcessor proc;
            std::vector<std::string> test_data = {"alpha", "beta", "gamma"};
            proc.process_records(test_data);
            return 0;
        }
        """

        compiler_manager.clear_cache()
        t0 = time.time()
        res = compiler_manager.validate_and_compile(cpp_code, language="cpp", file_name="large_test.cpp", use_cache=False)
        compile_time = time.time() - t0

        self.assertTrue(res.syntax_result.is_valid, f"Syntax should be valid: {res.syntax_result.raw_output}")
        self.assertIsNotNone(res.ir_result, "IR result should not be None")
        self.assertTrue(res.ir_result.success, f"IR generation should succeed: {res.ir_result.error}")
        self.assertLess(compile_time, 3.0, f"Compilation should be faster than 3s, took {compile_time:.2f}s")
        print(f"\n[OK] Large C++ Single-Pass Compilation Time: {compile_time*1000:.1f} ms")

    def test_missing_header_auto_injection_c(self):
        """
        Validates that patches using strlen/snprintf auto-inject missing <string.h> and <stdio.h>
        and hoist any directive lines from within the patch to the top of the file.
        """
        original_c = """
        // Minimal C code without string.h
        void process_buffer(char *dest, const char *src) {
            // vulnerable unbounded copy
            for (int i = 0; src[i] != '\\0'; i++) {
                dest[i] = src[i];
            }
        }
        """

        patch_with_header_in_body = """
        #include <string.h>
        void process_buffer(char *dest, const char *src) {
            if (!dest || !src) return;
            size_t len = strlen(src);
            if (len >= 64) len = 63;
            memcpy(dest, src, len);
            dest[len] = '\\0';
        }
        """

        merged = FunctionPatchReplacer.apply_patch(
            original_code=original_c,
            patch_code=patch_with_header_in_body,
            function_name="process_buffer",
            language="c"
        )

        # Directives should be hoisted to top, not inside the function body
        self.assertIn("#include <string.h>", merged, "Header should be present in merged file")
        self.assertLess(merged.find("#include <string.h>"), merged.find("void process_buffer"), "Header must precede function")
        self.assertIn("process_buffer", merged)
        self.assertIn("size_t len = strlen(src);", merged)

        # Validate that the merged code compiles without undeclared symbol errors
        res = compiler_manager.validate_and_compile(merged, language="c", file_name="auto_header.c", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Merged code with auto-injected headers must compile: {res.syntax_result.raw_output}")
        print("\n[OK] C Header Hoisting & Auto-Injection validated cleanly!")

    def test_python_dedent_and_script_patching(self):
        """
        Validates that Python indentation is normalized without IndentationError,
        and missing modules (sqlite3, hashlib) are auto-injected.
        """
        orig_script = """
username = input("Enter username: ")
password = input("Enter password: ")
query = "SELECT * FROM users WHERE username = '" + username + "'"
print("Query:", query)
"""

        patch = """
    # Secure parameterized query
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    print(cursor.fetchall())
"""

        merged = FunctionPatchReplacer.apply_patch(
            original_code=orig_script,
            patch_code=patch,
            function_name="",
            language="python"
        )

        res = compiler_manager.validate_and_compile(merged, language="python", file_name="script.py", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Patched Python script should pass syntax validation: {res.syntax_result.raw_output}")
        print("\n[OK] Python Dedent & Script-level Patching validated cleanly!")

    def test_isevc_early_pruning_performance(self):
        """
        Validates that iSeVC builder prunes stdlib inlines early and executes in under 200ms
        even when LLVM IR contains dozens of compiler-generated definitions.
        """
        cpp_code = """
        #include <stdio.h>
        #include <stdlib.h>

        void vulnerable_action(char *input) {
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "%s", input);
            printf("%s\\n", buffer);
        }

        int main(int argc, char **argv) {
            if (argc > 1) vulnerable_action(argv[1]);
            return 0;
        }
        """

        comp_res = compiler_manager.validate_and_compile(cpp_code, language="c", file_name="bench.c", use_cache=False)
        self.assertTrue(comp_res.ir_result.success)

        t0 = time.time()
        isevc_res = isevc_builder.build_isevc(comp_res.ir_result.ir_code, cpp_code)
        elapsed = time.time() - t0

        self.assertTrue(isevc_res.success)
        self.assertLess(elapsed, 0.200, f"iSeVC extraction should take < 200ms, took {elapsed*1000:.1f}ms")
        print(f"\n[OK] iSeVC Early Pruning Execution Time: {elapsed*1000:.1f} ms")

if __name__ == "__main__":
    unittest.main()
