import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    print("[OK] Health endpoint:", res.json())

def test_api_validate_syntax():
    # Test valid C code
    res = client.post("/api/validate-syntax", json={
        "code": "int main() { return 0; }",
        "language": "c"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    print("[OK] /api/validate-syntax (valid C): is_valid =", data["is_valid"])

    # Test invalid C code
    res = client.post("/api/validate-syntax", json={
        "code": "int main() { return 0 ",
        "language": "c"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is False
    assert len(data["errors"]) > 0
    print("[OK] /api/validate-syntax (invalid C): is_valid =", data["is_valid"], "Errors:", data["errors"][0]["message"])

def test_api_generate_ir():
    # Valid C code
    res = client.post("/api/generate-ir", json={
        "code": "int add(int a, int b) { return a + b; }",
        "language": "c"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["syntax_result"]["is_valid"] is True
    assert data["ir_result"] is not None
    assert data["ir_result"]["success"] is True
    assert "@add" in data["ir_result"]["ir_code"]
    print("[OK] /api/generate-ir (valid C): Generated IR successfully with function @add")

    # Invalid C code
    res = client.post("/api/generate-ir", json={
        "code": "int add(int a, int b) { return a + b ",
        "language": "c"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["syntax_result"]["is_valid"] is False
    assert data["ir_result"] is None
    print("[OK] /api/generate-ir (invalid C): Correctly rejected without generating IR")

def test_api_extract_isevc():
    vulnerable_code = """
    #include <string.h>
    void vuln_copy(char *src) {
        char buf[8];
        strcpy(buf, src);
    }
    """
    res = client.post("/api/extract-isevc", json={
        "code": vulnerable_code,
        "language": "c"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid_syntax"] is True
    assert data["ir_generated"] is True
    assert data["isevc"] is not None
    assert data["isevc"]["success"] is True
    assert len(data["isevc"]["functions"]) > 0
    assert "@vuln_copy" in data["isevc"]["semantic_summary"]
    print(f"[OK] /api/extract-isevc: Successfully extracted iSeVC (Reduced tokens by {data['isevc']['reduction_percentage']}%)")

def test_api_analyze_vulnerabilities():
    vulnerable_code = """
    #include <string.h>
    void process_token(const char *raw_token) {
        char token_buf[8];
        strcpy(token_buf, raw_token);
    }
    """
    res = client.post("/api/analyze-vulnerabilities", json={
        "code": vulnerable_code,
        "language": "c",
        "file_name": "token_processor.c"
    })
    assert res.status_code == 200
    data = res.json()
    if data.get("analysis_result") is None:
        print("[!] /api/analyze-vulnerabilities error:", data.get("error"))
    assert data["syntax_result"]["is_valid"] is True
    assert data["ir_generated"] is True
    assert data["analysis_result"] is not None, f"Analysis result is None: {data.get('error')}"
    assert data["analysis_result"]["is_vulnerable"] is True
    assert len(data["analysis_result"]["vulnerabilities"]) > 0
    vuln = data["analysis_result"]["vulnerabilities"][0]
    assert "CWE" in vuln["cwe_id"]
    assert len(vuln["patch_candidates"]) > 0
    print(f"[OK] /api/analyze-vulnerabilities: Successfully detected {vuln['cwe_id']} with patch '{vuln['patch_candidates'][0]['title']}'")

def test_api_verify_patch():
    orig_code = """
    #include <stdio.h>
    #include <string.h>
    void test_copy(char *src) {
        char buf[16];
        strcpy(buf, src);
    }
    """
    patch = """
    void test_copy(char *src) {
        char buf[16];
        if (!src) return;
        snprintf(buf, sizeof(buf), "%s", src);
    }
    """
    res = client.post("/api/verify-patch", json={
        "original_code": orig_code,
        "patch_code": patch,
        "function_name": "test_copy",
        "language": "c",
        "vulnerability_id": "VULN-001"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["syntax_valid"] is True
    assert data["ir_generated"] is True
    assert data["is_verified"] is True
    print(f"[OK] /api/verify-patch: Verified = {data['is_verified']} ({data['verification_message'][:80]}...)")

def test_api_generate_report():
    res = client.post("/api/generate-report", json={
        "project_name": "FlawFix Automated Test Suite",
        "file_name": "sample.c",
        "language": "c",
        "analysis_result": {
            "is_vulnerable": False,
            "total_vulnerabilities": 0,
            "vulnerabilities": [],
            "general_optimizations": [
                {
                    "title": "Compiler Inlining",
                    "description": "Mark hot helper functions as inline for speed",
                    "impact": "Lowers call overhead"
                }
            ],
            "summary": "Source code verified clean of memory safety and logic vulnerabilities.",
            "analysis_time_ms": 500.0
        }
    })
    assert res.status_code == 200
    data = res.json()
    assert "report_id" in data
    assert os.path.exists(data["file_path"])
    print(f"[OK] /api/generate-report: Created Report ID {data['report_id']} ({data['file_size_bytes']} bytes)")

    # Test downloading the report
    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 200
    assert dl_res.content.startswith(b"%PDF-")
    print(f"[OK] GET {data['download_url']}: Successfully downloaded valid PDF document")

if __name__ == "__main__":
    test_api_health()
    test_api_validate_syntax()
    test_api_generate_ir()
    test_api_extract_isevc()
    test_api_analyze_vulnerabilities()
    test_api_verify_patch()
    test_api_generate_report()
    print("\n[SUCCESS] ALL FASTAPI ENDPOINT TESTS PASSED (100% SUCCESS)!")
