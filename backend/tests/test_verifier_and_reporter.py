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

if __name__ == "__main__":
    unittest.main()
