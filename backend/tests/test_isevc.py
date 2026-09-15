import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.compilers.compiler_manager import compiler_manager
from backend.extractor.isevc_builder import isevc_builder

class TestiSeVCExtractor(unittest.TestCase):

    def test_buffer_overflow_extraction(self):
        code = """
        #include <string.h>
        void process_input(const char *input) {
            char buffer[16];
            strcpy(buffer, input);
        }
        """
        comp_res = compiler_manager.validate_and_compile(code, language="c")
        self.assertTrue(comp_res.syntax_result.is_valid)
        self.assertTrue(comp_res.ir_result.success)

        isevc_res = isevc_builder.build_isevc(comp_res.ir_result.ir_code, code)
        self.assertTrue(isevc_res.success)
        self.assertEqual(len(isevc_res.functions), 1)

        func = isevc_res.functions[0]
        self.assertEqual(func.function_name, "process_input")
        
        # Check dangerous call detection
        call_names = [c["function"] for c in func.critical_calls]
        self.assertTrue(any("strcpy" in name for name in call_names), f"Expected strcpy in calls: {call_names}")

        # Check memory allocations
        self.assertGreater(len(func.memory_allocations), 0)

        # Check reduction ratio
        self.assertGreater(isevc_res.reduction_percentage, 20.0)

        print("\n[OK] Test Buffer Overflow Extraction:")
        print(f"     -> Function: @{func.function_name}")
        print(f"     -> Dangerous calls detected: {call_names}")
        print(f"     -> Source lines covered: {func.source_lines_covered}")
        print(f"     -> Raw IR: {isevc_res.raw_ir_size_bytes}B, Pruned: {isevc_res.pruned_size_bytes}B (Reduced by {isevc_res.reduction_percentage}%)")

    def test_use_after_free_extraction(self):
        code = """
        #include <stdlib.h>
        void release_and_access() {
            int *ptr = (int *)malloc(sizeof(int));
            *ptr = 42;
            free(ptr);
            *ptr = 100;
        }
        """
        comp_res = compiler_manager.validate_and_compile(code, language="c")
        self.assertTrue(comp_res.syntax_result.is_valid)
        self.assertTrue(comp_res.ir_result.success)

        isevc_res = isevc_builder.build_isevc(comp_res.ir_result.ir_code, code)
        self.assertTrue(isevc_res.success)

        func = isevc_res.functions[0]
        call_names = [c["function"] for c in func.critical_calls]
        self.assertTrue(any("malloc" in name for name in call_names))
        self.assertTrue(any("free" in name for name in call_names))

        print("\n[OK] Test Use-After-Free Extraction:")
        print(f"     -> Memory management calls: {call_names}")
        print(f"     -> CFG Basic blocks: {[bb.label for bb in func.basic_blocks]}")

    def test_semantic_summary_prompt_generation(self):
        code = """
        #include <stdio.h>
        #include <string.h>
        int check_auth(char *user_input) {
            char password[8];
            strcpy(password, user_input);
            if (strcmp(password, "secret") == 0) {
                return 1;
            }
            return 0;
        }
        """
        comp_res = compiler_manager.validate_and_compile(code, language="c")
        isevc_res = isevc_builder.build_isevc(comp_res.ir_result.ir_code, code)

        self.assertIn("=== INTERMEDIATE SEMANTIC VULNERABILITY CONTEXT (iSeVC) ===", isevc_res.semantic_summary)
        self.assertIn("@check_auth", isevc_res.semantic_summary)
        self.assertIn("strcpy", isevc_res.semantic_summary)

        print("\n[OK] Test Semantic Summary Output:")
        print("--------------------------------------------------")
        print(isevc_res.semantic_summary[:400] + "\n... [truncated] ...")
        print("--------------------------------------------------")

if __name__ == "__main__":
    unittest.main()
