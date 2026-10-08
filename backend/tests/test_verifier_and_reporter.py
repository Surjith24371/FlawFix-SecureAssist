import unittest
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.models.verification_schema import VerifyPatchRequest, ReportRequest
from backend.models.ai_schema import SecurityAnalysisResult, VulnerabilityFinding, PatchCandidate, OptimizationSuggestion
from backend.verifier.patch_verifier import patch_verifier
from backend.reporter.pdf_generator import pdf_report_generator

class TestVerifierAndReporter(unittest.TestCase):

    def test_patch_verification_success(self):
        original_c = """
        #include <string.h>
        #include <stdio.h>
        void copy_data(const char *src) {
            char buf[16];
            strcpy(buf, src);
            printf("%s\\n", buf);
        }
        """

        secure_patch = """
        void copy_data(const char *src) {
            char buf[16];
            if (src == NULL) return;
            snprintf(buf, sizeof(buf), "%s", src);
            printf("%s\\n", buf);
        }
        """

        req = VerifyPatchRequest(
            original_code=original_c,
            patch_code=secure_patch,
            function_name="copy_data",
            language="c",
            file_name="copy.c",
            vulnerability_id="VULN-001"
        )
        res = patch_verifier.verify_patch(req)
        if not res.syntax_valid:
            print("[DEBUG] Patched Code:\n", res.verified_code)
            print("[DEBUG] Verification Message:\n", res.verification_message)
        self.assertTrue(res.syntax_valid, f"Patched code should have valid syntax: {res.verification_message}")
        self.assertTrue(res.ir_generated, "Patched code should generate LLVM IR")
        self.assertTrue(res.is_verified, f"Patch should be verified clean: {res.verification_message}")

        print("\n" + "="*60)
        print("  AUTOMATED PATCH VERIFICATION VERIFICATION REPORT")
        print("="*60)
        print(f"[OK] Is Verified:       {res.is_verified}")
        print(f"[OK] Syntax Valid:      {res.syntax_valid}")
        print(f"[OK] IR Recompiled:     {res.ir_generated}")
        print(f"[OK] Details:           {res.verification_message}")
        print(f"[OK] Verification Time: {res.analysis_time_ms} ms")
        print("="*60)

    def test_patch_verification_syntax_failure(self):
        original_c = """
        #include <string.h>
        void copy_data(const char *src) {
            char buf[16];
            strcpy(buf, src);
        }
        """

        broken_patch = """
        void copy_data(const char *src) {
            char buf[16]
            broken syntax without semicolon
        }
        """

        req = VerifyPatchRequest(
            original_code=original_c,
            patch_code=broken_patch,
            function_name="copy_data",
            language="c",
            file_name="copy.c"
        )
        res = patch_verifier.verify_patch(req)

        self.assertFalse(res.syntax_valid, "Broken patch must fail syntax check")
        self.assertFalse(res.is_verified, "Broken patch cannot be verified")
        self.assertIn("Syntax error", res.verification_message)
        print(f"\n[OK] Broken Patch Correctly Caught: {res.verification_message}")

    def test_pdf_report_generation(self):
        sample_analysis = SecurityAnalysisResult(
            is_vulnerable=True,
            total_vulnerabilities=1,
            vulnerabilities=[
                VulnerabilityFinding(
                    vulnerability_id="VULN-001",
                    title="Stack-based Buffer Overflow via strcpy",
                    cwe_id="CWE-120: Buffer Copy without Checking Size of Input",
                    severity="Critical",
                    function_name="copy_data",
                    affected_lines=[6],
                    root_cause="The function allocates 16 bytes on the stack and copies unbounded data with strcpy.",
                    security_impact="Remote attackers can trigger memory corruption and arbitrary code execution.",
                    recommendation="Use snprintf() or strncpy_s() with explicit destination size bounds.",
                    patch_candidates=[
                        PatchCandidate(
                            patch_id="patch_1",
                            title="Bounded snprintf replacement",
                            description="Replaces strcpy with bounded snprintf call.",
                            patched_code="void copy_data(const char *src) {\n    char buf[16];\n    if (!src) return;\n    snprintf(buf, sizeof(buf), \"%s\", src);\n}",
                            optimization_notes="Added null pointer guard and bounded stack allocation."
                        )
                    ]
                )
            ],
            general_optimizations=[
                OptimizationSuggestion(
                    title="Stack Buffer Optimization",
                    description="Align buffer on 64-bit boundary for faster cache line access.",
                    impact="Reduces cache misses by 15%"
                )
            ],
            summary="FlawFix detected 1 Critical vulnerability (CWE-120 Buffer Overflow). A secure patch has been generated and verified.",
            analysis_time_ms=1250.0
        )

        report_req = ReportRequest(
            project_name="FlawFix SecureAssist Demo",
            file_name="vuln_copy.c",
            language="c",
            analysis_result=sample_analysis,
            verified_patches=[
                {
                    "vulnerability_id": "VULN-001",
                    "status": "VERIFIED",
                    "message": "Re-compiled to LLVM IR and confirmed zero remaining vulnerabilities."
                }
            ]
        )

        res = pdf_report_generator.generate_report(report_req)

        self.assertTrue(os.path.exists(res.file_path), "PDF file must exist")
        self.assertGreater(res.file_size_bytes, 1000, "PDF size must be > 1KB")
        
        # Verify PDF magic bytes %PDF
        with open(res.file_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-", "File must have valid PDF header")

        print("\n" + "="*60)
        print("  REPORTLAB PDF GENERATOR VERIFICATION REPORT")
        print("="*60)
        print(f"[OK] Report ID:      {res.report_id}")
        print(f"[OK] PDF File Path:  {res.file_path}")
        print(f"[OK] PDF File Size:  {res.file_size_bytes} bytes")
        print(f"[OK] Download URL:   {res.download_url}")
        print(f"[OK] Magic Header:   %PDF- (Verified Valid Document)")
        print("="*60)

    def test_pdf_report_with_multiple_patches_and_original_code(self):
        """Test generating report with multiple patch candidates, original code context, and verification audit."""
        orig_code = """#include <stdio.h>
#include <string.h>

void process_buffer(const char *input) {
    char target[32];
    strcpy(target, input);
    printf("Processed: %s\\n", target);
}
"""
        patches = [
            PatchCandidate(
                patch_id="p1",
                title="Option 1: Defensive Precondition Bounds Check",
                approach_type="Defensive Validation",
                is_recommended=False,
                description="Validates that the input length is strictly less than target buffer capacity before copying.",
                patched_code="void process_buffer(const char *input) {\n    char target[32];\n    if (!input || strlen(input) >= sizeof(target)) return;\n    strcpy(target, input);\n}",
                optimization_notes="Early exit check avoids redundant stack operations."
            ),
            PatchCandidate(
                patch_id="p2",
                title="Option 2: Safe Standard API Replacement (Recommended)",
                approach_type="Safe API Replacement",
                is_recommended=True,
                description="Replaces unsafe strcpy with bounded snprintf guaranteeing explicit capacity limits and null termination.",
                patched_code="void process_buffer(const char *input) {\n    char target[32];\n    if (!input) return;\n    snprintf(target, sizeof(target), \"%s\", input);\n}",
                optimization_notes="Single-pass bounded formatting with zero manual pointer arithmetic."
            ),
            PatchCandidate(
                patch_id="p3",
                title="Option 3: Dynamic Buffer Allocation",
                approach_type="Architectural Refactor",
                is_recommended=False,
                description="Dynamically allocates heap buffer sized exactly to input length with guaranteed cleanup.",
                patched_code="void process_buffer(const char *input) {\n    if (!input) return;\n    char *target = malloc(strlen(input) + 1);\n    if (target) { strcpy(target, input); free(target); }\n}",
                optimization_notes="Removes arbitrary buffer size limits while ensuring memory safety."
            )
        ]

        analysis = SecurityAnalysisResult(
            is_vulnerable=True,
            total_vulnerabilities=1,
            vulnerabilities=[
                VulnerabilityFinding(
                    vulnerability_id="VULN-001",
                    title="Stack-based Buffer Overflow in process_buffer",
                    cwe_id="CWE-120: Buffer Copy without Checking Size of Input",
                    severity="Critical",
                    function_name="process_buffer",
                    affected_lines=[6],
                    root_cause="The function copies unbounded user data into a fixed 32-byte stack buffer via strcpy.",
                    security_impact="Attackers can overwrite adjacent stack frames, hijack control flow, and execute arbitrary code.",
                    recommendation="Replace unbounded strcpy with bounded snprintf or validate input length before copying.",
                    patch_candidates=patches
                )
            ],
            general_optimizations=[
                OptimizationSuggestion(
                    title="Compiler Stack Canary Alignment",
                    description="Ensure function prologue contains stack protector canaries for defense-in-depth.",
                    impact="Blocks stack smash exploitation attempts."
                )
            ],
            summary="FlawFix detected 1 Critical vulnerability. Three secure patch alternatives were synthesized and verified.",
            analysis_time_ms=850.0
        )

        req = ReportRequest(
            project_name="Secure Buffer Project",
            file_name="buffer_handler.c",
            language="c",
            analysis_result=analysis,
            original_code=orig_code,
            verified_patches=[
                {
                    "vulnerability_id": "VULN-001",
                    "status": "VERIFIED",
                    "message": "Re-compiled to LLVM IR and confirmed zero remaining vulnerabilities with zero regressions."
                }
            ]
        )

        res = pdf_report_generator.generate_report(req)
        self.assertTrue(os.path.exists(res.file_path))
        self.assertGreater(res.file_size_bytes, 2000)
        print(f"\n[OK] Multi-Patch Report Generated Successfully: {res.file_name} ({res.file_size_bytes} bytes)")

if __name__ == "__main__":
    unittest.main()
