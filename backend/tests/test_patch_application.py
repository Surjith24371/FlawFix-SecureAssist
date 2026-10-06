import unittest
from backend.verifier.patch_replacer import FunctionPatchReplacer
from backend.compilers.compiler_manager import compiler_manager

class TestPatchApplication(unittest.TestCase):

    def test_c_nested_braces_and_comments(self):
        original = """// Module Header Comment
#include <stdio.h>
#include <string.h>

// Vulnerability description comment
void process_buffer(char *input) {
    char buf[16];
    if (input != NULL) {
        // Nested block 1
        for (int i = 0; i < 5; i++) {
            // Inner comment with brace: }
            if (i == 2) {
                /* block comment { } */
                buf[i] = input[i];
            }
        }
        strcpy(buf, input);
    }
}

// Helper function that must not be deleted
int calculate_hash(const char *str) {
    return 42;
}

int main() {
    process_buffer("test");
    return 0;
}
"""
        patch = """// Repaired version
void process_buffer(char *input) {
    char buf[16];
    if (input != NULL) {
        snprintf(buf, sizeof(buf), "%s", input);
    }
}"""
        merged = FunctionPatchReplacer.apply_patch(original, patch, "process_buffer", "c")

        # 1. Check surrounding comments and functions preserved
        self.assertIn("// Module Header Comment", merged)
        self.assertIn("// Vulnerability description comment", merged)
        self.assertIn("int calculate_hash(const char *str) {", merged)
        self.assertIn("int main() {", merged)

        # 2. Check old code replaced
        self.assertNotIn("strcpy(buf, input);", merged)
        self.assertIn("snprintf(buf, sizeof(buf)", merged)

        # 3. Check syntax of complete merged source code passes Clang
        res = compiler_manager.validate_and_compile(merged, "c", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Patched code syntax validation failed: {res.syntax_result.errors}")
        print("\n[OK] test_c_nested_braces_and_comments: Successfully applied patch without corrupting braces or comments!")

    def test_python_patch_application(self):
        original = """# Global module comment
import hashlib

# Database query helper
def execute_query(q):
    return q

# Vulnerable login handler
def login_user(username, password):
    # Insecure query format
    query = f"SELECT * FROM users WHERE user = '{username}'"
    return execute_query(query)

def logout_user(username):
    print("User logged out")
"""
        patch = """def login_user(username, password):
    # Secure parameterized query
    query = "SELECT * FROM users WHERE user = %s"
    return execute_query((query, (username,)))"""

        merged = FunctionPatchReplacer.apply_patch(original, patch, "login_user", "python")

        self.assertIn("# Global module comment", merged)
        self.assertIn("def execute_query(q):", merged)
        self.assertIn("def logout_user(username):", merged)
        self.assertIn("def login_user(username, password):", merged)
        self.assertIn("# Secure parameterized query", merged)
        self.assertNotIn("f\"SELECT * FROM users", merged)

        res = compiler_manager.validate_and_compile(merged, "python", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Python patched code syntax validation failed: {res.syntax_result.errors}")
        print("\n[OK] test_python_patch_application: Successfully replaced Python function and validated syntax!")

    def test_multiple_vulnerable_functions_independent_patching(self):
        original = """#include <stdio.h>
#include <string.h>

void vuln_func_one(char *s) {
    char b1[10];
    strcpy(b1, s);
}

void safe_middle_func() {
    printf("Safe\\n");
}

void vuln_func_two(char *s) {
    char b2[20];
    strcpy(b2, s);
}
"""
        patch_one = """void vuln_func_one(char *s) {
    char b1[10];
    if (s) snprintf(b1, sizeof(b1), "%s", s);
}"""

        # Patch function one
        merged1 = FunctionPatchReplacer.apply_patch(original, patch_one, "vuln_func_one", "c")
        self.assertIn("vuln_func_two(char *s)", merged1)
        self.assertIn("safe_middle_func()", merged1)
        self.assertIn("snprintf(b1", merged1)

        patch_two = """void vuln_func_two(char *s) {
    char b2[20];
    if (s) snprintf(b2, sizeof(b2), "%s", s);
}"""

        # Patch function two on top of merged1
        merged2 = FunctionPatchReplacer.apply_patch(merged1, patch_two, "vuln_func_two", "c")
        self.assertIn("snprintf(b1", merged2)
        self.assertIn("snprintf(b2", merged2)
        self.assertIn("safe_middle_func()", merged2)

        res = compiler_manager.validate_and_compile(merged2, "c", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Multi-function patched code syntax failed: {res.syntax_result.errors}")
        print("\n[OK] test_multiple_vulnerable_functions_independent_patching: Both functions cleanly patched without collision!")

    def test_python_sqlite_patch_detection_and_syntax_verification(self):
        """
        Regression test: When applying a Python patch (like the user's sqlite3 parameterized query fix),
        the system must NOT fall back to Clang (C compiler) with [UnknownTypeName] or [SyntaxError] preprocessing errors.
        It must accurately detect Python and validate syntax cleanly.
        """
        original = '''import sqlite3

username = input("Enter username: ")

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

print(cursor.fetchall())'''

        patch = '''import sqlite3

username = input("Enter username: ")

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Use parameterized query to prevent SQL injection
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

print(cursor.fetchall())'''

        # Test 1: Language detection with ambiguous or default C inputs
        lang_detected_from_default = compiler_manager.detect_language("c", None, code=patch)
        self.assertEqual(lang_detected_from_default, "python", "Failed to detect Python when language='c' (default) but code is Python")

        lang_detected_from_plaintext = compiler_manager.detect_language("plaintext", None, code=patch)
        self.assertEqual(lang_detected_from_plaintext, "python", "Failed to detect Python when language='plaintext' but code is Python")

        lang_detected_from_none = compiler_manager.detect_language(None, None, code=patch)
        self.assertEqual(lang_detected_from_none, "python", "Failed to detect Python when language=None but code is Python")

        lang_detected_from_ext = compiler_manager.detect_language("c", "app.py", code=patch)
        self.assertEqual(lang_detected_from_ext, "python", "Failed to detect Python from filename extension app.py")

        # Test 2: Apply patch
        merged = FunctionPatchReplacer.apply_patch(original, patch, None, "python")
        self.assertIn("cursor.execute(query, (username,))", merged)

        # Test 3: Validate and compile with language='c' (simulating old client passing 'c' or schema default)
        comp_res = compiler_manager.validate_and_compile(merged, language="c", use_cache=False)
        self.assertEqual(comp_res.language, "python", f"Expected detected language 'python', got {comp_res.language}")
        self.assertTrue(comp_res.syntax_result.is_valid, f"Syntax validation failed on valid Python patch: {comp_res.syntax_result.errors}")
        self.assertIsNotNone(comp_res.ir_result, "IR generation failed for Python patch")
        self.assertTrue(comp_res.ir_result.success, f"IR generation error: {comp_res.ir_result.error}")
        print("\n[OK] test_python_sqlite_patch_detection_and_syntax_verification: Python SQLite patch correctly detected and validated without Clang syntax errors!")

    def test_cpp_patch_application_and_verification(self):
        original = """#include <iostream>
#include <cstring>

class DataHandler {
public:
    void process_data(const char *input) {
        char buf[16];
        strcpy(buf, input);
    }
};

int main() {
    DataHandler dh;
    dh.process_data("hello");
    return 0;
}
"""
        patch = """    void process_data(const char *input) {
        char buf[16];
        if (input != nullptr) {
            snprintf(buf, sizeof(buf), "%s", input);
        }
    }"""
        merged = FunctionPatchReplacer.apply_patch(original, patch, "DataHandler::process_data(const char *input)", "cpp")
        self.assertIn("snprintf(buf, sizeof(buf)", merged)
        self.assertIn("class DataHandler", merged)
        self.assertIn("int main()", merged)
        self.assertNotIn("strcpy(buf, input)", merged)

        res = compiler_manager.validate_and_compile(merged, language="cpp", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"C++ patched code syntax failed: {res.syntax_result.errors}")
        print("\n[OK] test_cpp_patch_application_and_verification: C++ patch cleanly applied and verified!")

    def test_rust_patch_application_and_verification(self):
        original = """pub fn process_input(input: &[u8]) -> Result<(), &'static str> {
    let mut buf = [0u8; 16];
    for i in 0..input.len() {
        buf[i] = input[i];
    }
    Ok(())
}

fn main() {
    let data = [1u8; 4];
    let _ = process_input(&data);
}
"""
        patch = """pub fn process_input(input: &[u8]) -> Result<(), &'static str> {
    let mut buf = [0u8; 16];
    let len = std::cmp::min(input.len(), buf.len());
    buf[..len].copy_from_slice(&input[..len]);
    Ok(())
}"""
        merged = FunctionPatchReplacer.apply_patch(original, patch, "pub fn process_input(input: &[u8])", "rust")
        self.assertIn("copy_from_slice", merged)
        self.assertIn("fn main()", merged)

        res = compiler_manager.validate_and_compile(merged, language="rust", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Rust patched code syntax failed: {res.syntax_result.errors}")
        print("\n[OK] test_rust_patch_application_and_verification: Rust patch cleanly applied and verified!")

    def test_java_patch_application_and_verification(self):
        original = """public class VulnerableClass {
    public void vulnerableFunc(byte[] input) throws Exception {
        byte[] buf = new byte[16];
        System.arraycopy(input, 0, buf, 0, input.length);
    }

    public static void main(String[] args) {
        try {
            new VulnerableClass().vulnerableFunc(new byte[4]);
        } catch (Exception e) {}
    }
}
"""
        patch = """    public void vulnerableFunc(byte[] input) throws Exception {
        byte[] buf = new byte[16];
        if (input != null) {
            int len = Math.min(input.length, buf.length);
            System.arraycopy(input, 0, buf, 0, len);
        }
    }"""
        merged = FunctionPatchReplacer.apply_patch(original, patch, "VulnerableClass.vulnerableFunc(byte[] input)", "java")
        self.assertIn("Math.min", merged)
        self.assertIn("public class VulnerableClass", merged)
        self.assertIn("public static void main", merged)

        res = compiler_manager.validate_and_compile(merged, language="java", use_cache=False)
        self.assertTrue(res.syntax_result.is_valid, f"Java patched code syntax failed: {res.syntax_result.errors}")
        print("\n[OK] test_java_patch_application_and_verification: Java patch cleanly applied and verified!")

if __name__ == "__main__":
    unittest.main()
