import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.compilers.compiler_manager import compiler_manager

class TestCompilerPipeline(unittest.TestCase):

    def test_c_valid_syntax_and_ir(self):
        code = """
        #include <stdio.h>
        int main() {
            int a = 10;
            int b = 20;
            return a + b;
        }
        """
        res = compiler_manager.validate_and_compile(code, language="c")
        self.assertTrue(res.syntax_result.is_valid, "Valid C code should pass syntax check")
        self.assertEqual(len(res.syntax_result.errors), 0)
        self.assertIsNotNone(res.ir_result, "IR result should be generated for valid syntax")
        self.assertTrue(res.ir_result.success, "LLVM IR generation should succeed")
        self.assertIn("@main", res.ir_result.ir_code, "LLVM IR should contain @main function")
        print("\n[OK] Test C Valid Code: Passed syntax check & generated LLVM IR.")

    def test_c_invalid_syntax_stops_pipeline(self):
        # Missing closing brace and semicolon
        code = """
        #include <stdio.h>
        int main() {
            int a = 10
            return a +
        """
        res = compiler_manager.validate_and_compile(code, language="c")
        self.assertFalse(res.syntax_result.is_valid, "Invalid C code should fail syntax check")
        self.assertGreater(len(res.syntax_result.errors), 0, "Should contain syntax error details")
        self.assertIsNone(res.ir_result, "IR generation should NOT run when syntax fails")
        print(f"\n[OK] Test C Invalid Syntax: Correctly blocked IR generation. Found {len(res.syntax_result.errors)} errors.")
        for err in res.syntax_result.errors:
            print(f"     -> Line {err.line}, Col {err.column}: {err.message}")

    def test_python_valid_syntax_and_ir(self):
        code = """
def calculate_sum(a, b):
    result = a + b
    return result
        """
        res = compiler_manager.validate_and_compile(code, language="python")
        self.assertTrue(res.syntax_result.is_valid, "Valid Python code should pass syntax check")
        self.assertIsNotNone(res.ir_result, "IR result should be generated")
        self.assertTrue(res.ir_result.success, "Python IR generation should succeed")
        self.assertIn("@calculate_sum", res.ir_result.ir_code)
        print("\n[OK] Test Python Valid Code: Passed syntax check & generated IR.")

    def test_python_invalid_syntax_stops_pipeline(self):
        code = """
def broken_function(
    return "Missing parenthesis and colon"
        """
        res = compiler_manager.validate_and_compile(code, language="python")
        self.assertFalse(res.syntax_result.is_valid, "Invalid Python code should fail syntax check")
        self.assertGreater(len(res.syntax_result.errors), 0)
        self.assertIsNone(res.ir_result, "IR generation must be skipped on syntax failure")
        print(f"\n[OK] Test Python Invalid Syntax: Correctly caught: {res.syntax_result.errors[0].message}")

if __name__ == "__main__":
    unittest.main()
