import sys
sys.path.insert(0, "d:/FlawFix")
from backend.compilers.compiler_manager import compiler_manager
from backend.extractor.isevc_builder import isevc_builder

code = """import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
password = input("Enter password: ")
print(hash_password(password))
"""

comp = compiler_manager.validate_and_compile(code, 'python', 'hash_test.py')
print("=== IR OUTPUT ===")
print(comp.ir_result.ir_code)
isevc = isevc_builder.build_isevc(comp.ir_result.ir_code, code)
print("=== iSeVC SUMMARY ===")
print(isevc.semantic_summary)
