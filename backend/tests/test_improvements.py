import unittest
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.compilers.compiler_manager import compiler_manager
from backend.verifier.patch_replacer import FunctionPatchReplacer
from backend.verifier.patch_verifier import patch_verifier
from backend.models.verification_schema import VerifyPatchRequest
from backend.models.ai_schema import PatchCandidate, VulnerabilityFinding
from backend.extractor.isevc_builder import isevc_builder
from backend.compilers.c_compiler import CCompiler

class TestFlawFixImprovements(unittest.TestCase):

    def test_A_multiple_patch_schema_and_candidates(self):
        """Test A: Verifies that 3 distinct secure patch candidates can be structured and associated."""
        patches = [
            PatchCandidate(
                patch_id="patch_1",
                title="Option 1: Defensive Bounds-Checking",
                description="Validates length before copying into destination buffer.",
                patched_code="void process(char *src) { char b[16]; if (strlen(src) < 16) strcpy(b, src); }",
                approach_type="Defensive Validation",
                optimization_notes="Early exit avoids redundant stack ops."
            ),
            PatchCandidate(
                patch_id="patch_2",
                title="Option 2: Safe Standard API Replacement",
                description="Replaces strcpy with snprintf bounded to sizeof(buf).",
                patched_code="void process(char *src) { char b[16]; snprintf(b, sizeof(b), \"%s\", src); }",
                approach_type="Safe API Replacement",
                optimization_notes="Guarantees null termination."
            ),
            PatchCandidate(
                patch_id="patch_3",
                title="Option 3: Dynamic Heap Allocation",
                description="Dynamically allocates memory to fit input size safely.",
                patched_code="void process(char *src) { char *b = malloc(strlen(src)+1); if (b) { strcpy(b, src); free(b); } }",
                approach_type="Architectural Refactor",
                optimization_notes="Eliminates fixed buffer size limitations."
            )
        ]
        vuln = VulnerabilityFinding(
            vulnerability_id="VULN-001",
            title="Stack-based Buffer Overflow in process",
            cwe_id="CWE-120",
            severity="High",
            function_name="process",
            affected_lines=[5],
            root_cause="Unbounded memory copy",
            security_impact="Potential buffer overwrite",
            recommendation="Use bounded alternatives",
            patch_candidates=patches
        )
        self.assertEqual(len(vuln.patch_candidates), 3)
        self.assertEqual(vuln.patch_candidates[0].approach_type, "Defensive Validation")
        self.assertEqual(vuln.patch_candidates[1].approach_type, "Safe API Replacement")
        self.assertEqual(vuln.patch_candidates[2].approach_type, "Architectural Refactor")
        print("\n[OK] Test A: Multiple (3) distinct patch alternatives supported and validated.")

    def test_B_comment_handling_no_false_syntax_errors(self):
        """Test B: Code containing single-line and multi-line comments must not trigger syntax errors."""
        c_code = """/*
 * Multi-line header comment
 * System: FlawFix SecureAssist
 */
#include <stdio.h>
#include <string.h>

// Single line comment before function
void vulnerable_copy(const char *input) {
    // Comment inside function with symbols: { [ ( // ) ] }
    char buffer[16];
    /* Multi-line comment inside
       with nested slashes */
    if (input != NULL) {
        // Comment before dangerous call
        strcpy(buffer, input);
    }
}
// Comment after function
"""
        res = compiler_manager.validate_and_compile(c_code, "c", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Comments should not be flagged as syntax errors: {res.syntax_result.errors}")
        self.assertEqual(len(res.syntax_result.errors), 0)
        self.assertIsNotNone(res.ir_result)
        self.assertTrue(res.ir_result.success)
        print("\n[OK] Test B: Single and multi-line comments preserved without false syntax errors.")

    def test_C_patch_application_nested_braces_and_validation(self):
        """Test C: Selected patch applied to nested blocks without truncating surrounding code."""
        orig_code = """#include <stdio.h>
#include <string.h>

// Important function comment
void process_records(char *data) {
    char temp[32];
    if (data) {
        for (int i = 0; i < 3; i++) {
            while (*data == ' ') data++;
            if (*data == '\\0') break;
        }
        strcpy(temp, data);
    }
}

int calculate_score() {
    return 100;
}
"""
        patch_code = """void process_records(char *data) {
    char temp[32];
    if (data) {
        snprintf(temp, sizeof(temp), "%s", data);
    }
}"""
        merged = FunctionPatchReplacer.apply_patch(orig_code, patch_code, "process_records", "c")
        
        # Verify surrounding code is preserved
        self.assertIn("int calculate_score() {", merged)
        self.assertIn("return 100;", merged)
        self.assertIn("// Important function comment", merged)
        self.assertNotIn("strcpy(temp, data);", merged)

        # Validate complete updated source code
        res = compiler_manager.validate_and_compile(merged, "c", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Merged code failed syntax validation: {res.syntax_result.errors}")
        print("\n[OK] Test C: Patch application correctly handled nested braces and passed complete source validation.")

    def test_D_multiple_vulnerable_functions_association(self):
        """Test D: Multiple vulnerable functions in the same file patched independently."""
        orig = """#include <stdio.h>
#include <string.h>

void func_alpha(char *a) {
    char b1[8];
    strcpy(b1, a);
}

void middle_clean_func() {
    printf("Clean\\n");
}

void func_beta(char *b) {
    char b2[16];
    strcpy(b2, b);
}
"""
        patch_beta = """void func_beta(char *b) {
    char b2[16];
    if (b) snprintf(b2, sizeof(b2), "%s", b);
}"""
        # Patch second function only
        merged = FunctionPatchReplacer.apply_patch(orig, patch_beta, "func_beta", "c")
        self.assertIn("void func_alpha(char *a) {", merged)
        self.assertIn("strcpy(b1, a);", merged)  # func_alpha untouched
        self.assertIn("void middle_clean_func() {", merged)
        self.assertIn("snprintf(b2, sizeof(b2)", merged)  # func_beta patched

        res = compiler_manager.validate_and_compile(merged, "c", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid)
        print("\n[OK] Test D: Multiple vulnerable functions handled with exact association.")

    def test_E_syntax_error_detection_and_stop_gate(self):
        """Test E: Blocking syntax errors report line, column, error category, explanation and STOP before LLVM IR."""
        broken_c = """#include <stdio.h>
int main() {
    int x = 10
    int y = 20;
    return x + y;
}
"""
        res = compiler_manager.validate_and_compile(broken_c, "c", use_cache=False)
        self.assertFalse(res.syntax_result.is_valid)
        self.assertIsNone(res.ir_result, "LLVM IR generation MUST NOT run when syntax errors exist!")
        self.assertGreater(len(res.syntax_result.errors), 0)

        err = res.syntax_result.errors[0]
        self.assertEqual(err.line, 3)
        self.assertIsNotNone(err.column)

        self.assertEqual(err.error_type, "MissingSemicolon")
        self.assertIn("semicolon", err.explanation.lower())
        self.assertIn("original_message", err.model_dump())
        print(f"\n[OK] Test E: Syntax error caught -> Category: {err.error_type}, Line: {err.line}, Col: {err.column}, Stopped LLVM IR.")

    def test_F_patch_verification_pipeline(self):
        """Test F: Automated patch verification with syntax validation and iSeVC extraction."""
        original_c = """#include <string.h>
#include <stdio.h>
void vuln_worker(const char *src) {
    char buf[16];
    strcpy(buf, src);
}
"""
        valid_patch = """void vuln_worker(const char *src) {
    char buf[16];
    if (src) snprintf(buf, sizeof(buf), "%s", src);
}"""
        # Test broken patch rejection
        broken_patch = """void vuln_worker(const char *src) {
            broken syntax
        }"""
        req_broken = VerifyPatchRequest(
            original_code=original_c,
            patch_code=broken_patch,
            function_name="vuln_worker",
            language="c"
        )
        res_broken = patch_verifier.verify_patch(req_broken)
        self.assertFalse(res_broken.syntax_valid)
        self.assertFalse(res_broken.is_verified)
        self.assertIn("Syntax error in patched code", res_broken.verification_message)

        # Test valid patch compiles and generates IR and iSeVC
        applied_clean = patch_verifier.apply_patch_to_code(original_c, valid_patch, "vuln_worker", "c")
        comp = compiler_manager.validate_and_compile(applied_clean, "c", use_cache=False)
        self.assertTrue(comp.syntax_result.is_valid)
        self.assertTrue(comp.ir_result.success)

        isevc = isevc_builder.build_isevc(comp.ir_result.ir_code, applied_clean)
        self.assertTrue(isevc.success)
        self.assertIn("@vuln_worker", isevc.semantic_summary)
        print("\n[OK] Test F: Complete patch verification pipeline tested (syntax gate, IR recompilation, iSeVC extraction).")

    def test_G_small_source_llvm_performance_caching(self):
        """Test G: Performance caching avoids recompiling unchanged code."""
        code = """#include <stdio.h>
int test_func(int a, int b) {
    return a * b + 42;
}
"""
        compiler_manager.clear_cache()
        t0 = time.time()
        res1 = compiler_manager.validate_and_compile(code, "c", use_cache=True)
        time1 = time.time() - t0

        t1 = time.time()
        res2 = compiler_manager.validate_and_compile(code, "c", use_cache=True)
        time2 = time.time() - t1

        self.assertTrue(res1.syntax_result.is_valid)
        self.assertTrue(res2.syntax_result.is_valid)
        # Second cached call should be virtually instantaneous (< 5ms)
        self.assertLess(time2, 0.01, f"Cached compile call should take < 10ms, took {time2*1000:.2f}ms")
        print(f"\n[OK] Test G: LLVM caching verified: 1st compile = {time1*1000:.2f}ms, 2nd cached = {time2*1000:.2f}ms")

    def test_H_llvm_timeout_handling(self):
        """Test H: Compiler timeout is handled cleanly with the specific developer-facing message."""
        # Create a mock compiler with 0.0001s timeout to test timeout handling
        orig_timeout = os.environ.get("FLAWFIX_COMPILER_TIMEOUT")
        try:
            # Test that timeout returns the designated error message
            from backend.compilers import c_compiler
            old_timeout = c_compiler.COMPILER_TIMEOUT
            c_compiler.COMPILER_TIMEOUT = 0.00001 # force immediate timeout

            compiler = CCompiler()
            res = compiler.generate_llvm_ir("int main() { return 0; }")
            self.assertFalse(res.success)
            self.assertEqual(
                res.error,
                "LLVM IR generation timed out while processing the source code. Security analysis could not be completed."
            )
            print(f"\n[OK] Test H: Timeout cleanly captured with designated message: '{res.error}'")
        finally:
            if orig_timeout:
                os.environ["FLAWFIX_COMPILER_TIMEOUT"] = orig_timeout
            c_compiler.COMPILER_TIMEOUT = old_timeout

    def test_I_recommended_patch_designation(self):
        """Test I: Verifies that one patch is designated as (Recommended) according to remediation guidelines."""
        # 1. PatchCandidate accepts and defaults is_recommended
        p1 = PatchCandidate(
            patch_id="p1",
            title="Option 1: Defensive Bounds-Checking",
            description="Bounds check",
            patched_code="void foo(){}",
            approach_type="Defensive Validation"
        )
        self.assertFalse(p1.is_recommended)

        p2 = PatchCandidate(
            patch_id="p2",
            title="Option 2: Safe API Replacement (Recommended)",
            description="Safe API",
            patched_code="void foo(){}",
            approach_type="Safe API Replacement",
            is_recommended=True
        )
        self.assertTrue(p2.is_recommended)
        self.assertIn("(Recommended)", p2.title)

        # 2. Test fallback logic when AI response has patches without explicit is_recommended
        patches = [
            PatchCandidate(patch_id="p1", title="Option 1: Defensive Validation", description="desc", patched_code="code"),
            PatchCandidate(patch_id="p2", title="Option 2: Safe API Replacement", description="desc", patched_code="code", approach_type="Safe API Replacement"),
            PatchCandidate(patch_id="p3", title="Option 3: Architectural Refactor", description="desc", patched_code="code")
        ]
        
        # Simulate vulnerability_detector logic
        has_rec = any(pt.is_recommended for pt in patches)
        if not has_rec and patches:
            rec_target = patches[1] if len(patches) > 1 else patches[0]
            rec_target.is_recommended = True

        for pt in patches:
            if pt.is_recommended:
                if "(recommended)" not in pt.title.lower():
                    pt.title = f"{pt.title.strip()} (Recommended)"
            else:
                pt.title = pt.title.replace(" (Recommended)", "").replace("(Recommended)", "").strip()

        # Check that exactly one patch is marked as is_recommended and has (Recommended) in its title
        recommended_patches = [pt for pt in patches if pt.is_recommended]
        self.assertEqual(len(recommended_patches), 1)
        self.assertEqual(recommended_patches[0].patch_id, "p2")
        self.assertIn("(Recommended)", recommended_patches[0].title)
        self.assertNotIn("(Recommended)", patches[0].title)
        self.assertNotIn("(Recommended)", patches[2].title)
        print("\n[OK] Test I: Recommended patch candidate designated, tagged with '(Recommended)', and validated.")

    def test_J_java_duplicate_class_prevention(self):
        """Test J: Verifies that applying a Java patch never produces duplicate class definitions."""
        from backend.compilers.java_compiler import JavaCompiler

        orig_java = """import java.io.*;

public class FileReaderApp {
    public static void main(String[] args) {
        System.out.println("Main runner");
    }

    public void readFile(String path) {
        File file = new File(path);
    }
}
"""

        # Case 1: AI patch is wrapped in redundant class wrapper
        patch_wrapped = """public class FileReaderApp {
    public void readFile(String path) {
        if (path == null || path.contains("..")) {
            throw new IllegalArgumentException("Invalid path");
        }
        File file = new File(path);
    }
}"""

        patched_code_1 = FunctionPatchReplacer.apply_patch(orig_java, patch_wrapped, "readFile", "java")
        self.assertEqual(patched_code_1.count("class FileReaderApp"), 1, "Must never define class FileReaderApp twice!")
        self.assertIn("main(String[] args)", patched_code_1, "Must preserve existing main method!")
        self.assertIn("IllegalArgumentException", patched_code_1, "Must contain patched logic!")

        res1 = JavaCompiler().validate_syntax(patched_code_1, "FileReaderApp.java")
        self.assertTrue(res1.is_valid, f"Patched code should compile with 0 syntax errors: {res1.errors}")

        # Case 2: AI patch replaces entire class
        patch_full = """public class FileReaderApp {
    public static void main(String[] args) {
        System.out.println("Updated runner");
    }

    public void readFile(String path) {
        if (path == null) return;
        File file = new File(path);
    }
}"""

        patched_code_2 = FunctionPatchReplacer.apply_patch(orig_java, patch_full, "readFile", "java")
        self.assertEqual(patched_code_2.count("class FileReaderApp"), 1, "Must never define class FileReaderApp twice!")
        self.assertIn("Updated runner", patched_code_2)

        res2 = JavaCompiler().validate_syntax(patched_code_2, "FileReaderApp.java")
        self.assertTrue(res2.is_valid, f"Full class patch should compile with 0 syntax errors: {res2.errors}")

        # Case 3: AI patch is pure method without class wrapper
        patch_method_only = """    public void readFile(String path) {
        if (path == null) return;
        File file = new File(path);
    }"""

        patched_code_3 = FunctionPatchReplacer.apply_patch(orig_java, patch_method_only, "readFile", "java")
        self.assertEqual(patched_code_3.count("class FileReaderApp"), 1)
        res3 = JavaCompiler().validate_syntax(patched_code_3, "FileReaderApp.java")
        self.assertTrue(res3.is_valid, f"Method-only patch should compile with 0 syntax errors: {res3.errors}")

        print("\n[OK] Test J: Java duplicate class prevention verified across wrapped, full, and method-only patches.")

if __name__ == "__main__":
    unittest.main()
