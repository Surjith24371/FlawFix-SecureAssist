import unittest
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.models.ai_schema import FullAnalysisRequest
from backend.ai.vulnerability_detector import vulnerability_detector

class TestAIVulnerabilityDetection(unittest.TestCase):

    def test_buffer_overflow_detection_and_patching(self):
        vulnerable_c_code = """
        #include <string.h>
        #include <stdio.h>
        
        void copy_user_data(const char *user_input) {
            char target_buffer[16];
            // Vulnerable: Unbounded string copy
            strcpy(target_buffer, user_input);
            printf("Copied: %s\\n", target_buffer);
        }
        """
        req = FullAnalysisRequest(
            code=vulnerable_c_code,
            language="c",
            file_name="vuln_copy.c"
        )
        res = vulnerability_detector.analyze_source_code(req)

        self.assertTrue(res.syntax_result.is_valid, "Syntax should be valid")
        self.assertTrue(res.ir_generated, "LLVM IR should be generated")
        self.assertIsNotNone(res.analysis_result, f"Analysis result should not be None: {res.error}")
        
        analysis = res.analysis_result
        self.assertTrue(analysis.is_vulnerable, "Code should be detected as vulnerable")
        self.assertGreater(analysis.total_vulnerabilities, 0)

        vuln = analysis.vulnerabilities[0]
        self.assertIn("120", vuln.cwe_id.upper() + vuln.title.upper(), "Should identify CWE-120 or Buffer Overflow")
        self.assertIn(vuln.severity, ["High", "Critical"])
        self.assertTrue(len(vuln.root_cause) > 20, "Root cause must be detailed (XAI)")
        self.assertTrue(len(vuln.security_impact) > 20, "Security impact must be detailed (XAI)")
        self.assertTrue(len(vuln.patch_candidates) > 0, "Must provide secure patch candidates")

        patch = vuln.patch_candidates[0]
        self.assertTrue(len(patch.patched_code) > 10, "Patch candidate must have code")

        print("\n" + "="*60)
        print("  AI VULNERABILITY DETECTION & XAI VERIFICATION REPORT")
        print("="*60)
        print(f"[OK] Vulnerability ID: {vuln.vulnerability_id}")
        print(f"[OK] Title:            {vuln.title}")
        print(f"[OK] CWE:              {vuln.cwe_id}")
        print(f"[OK] Severity:         {vuln.severity}")
        print(f"[OK] Affected Lines:   {vuln.affected_lines}")
        print(f"[OK] XAI Root Cause:   {vuln.root_cause[:120]}...")
        print(f"[OK] Security Impact:  {vuln.security_impact[:120]}...")
        print(f"[OK] Secure Patch Fix: {patch.title}")
        print(f"[OK] Optimization:     {patch.optimization_notes}")
        print(f"[OK] Response Time:    {analysis.analysis_time_ms} ms")
        print("="*60)

    def test_clean_code_analysis(self):
        clean_code = """
        #include <stdio.h>
        #include <limits.h>
        
        int safe_add(int a, int b) {
            if (a > 0 && b > INT_MAX - a) {
                return -1; // Overflow prevented
            }
            if (a < 0 && b < INT_MIN - a) {
                return -1; // Underflow prevented
            }
            return a + b;
        }
        """
        req = FullAnalysisRequest(
            code=clean_code,
            language="c",
            file_name="safe_add.c"
        )
        res = vulnerability_detector.analyze_source_code(req)

        self.assertTrue(res.syntax_result.is_valid)
        self.assertIsNotNone(res.analysis_result)
        print(f"\n[OK] Clean Code Analysis Summary: {res.analysis_result.summary}")
        print(f"[OK] Clean Code Is Vulnerable: {res.analysis_result.is_vulnerable} (Vulns: {res.analysis_result.total_vulnerabilities})")
        if res.analysis_result.vulnerabilities:
            for v in res.analysis_result.vulnerabilities:
                print(f"     -> Flagged: {v.title} ({v.cwe_id})")

if __name__ == "__main__":
    unittest.main()
