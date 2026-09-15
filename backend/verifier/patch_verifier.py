import re
import time
from typing import Optional, Tuple
from backend.models.verification_schema import VerifyPatchRequest, VerifyPatchResponse
from backend.compilers.compiler_manager import compiler_manager
from backend.extractor.isevc_builder import isevc_builder
from backend.ai.gemini_client import gemini_client

VERIFICATION_SYSTEM_INSTRUCTION = """
You are a Principal Compiler and Code Verification Security Engineer.
Your task is to verify whether a proposed security patch eliminates a specific detected vulnerability
WITHOUT introducing syntax errors, semantic regressions, or new security vulnerabilities.

RULES:
1. Ensure the patched code fulfills the original function's purpose.
2. Check that memory safety issues, buffer sizes, pointer boundaries, and type safety are properly addressed.
3. Output STRICT JSON only.
"""

class PatchVerifier:
    """
    Automated Patch Verification Engine (SRS Modules 5.3.7 & 5.3.8).
    Compiles patched code into LLVM IR, extracts new iSeVCs, and verifies vulnerability elimination.
    """

    def apply_patch_to_code(self, original_code: str, patch_code: str, function_name: Optional[str] = None) -> str:
        """
        Integrates a function-level patch into the original source code.
        """
        clean_patch = patch_code.strip()

        # If patch already appears to be a full program with main/headers or identical line count
        if ("#include" in clean_patch or "import " in clean_patch) and len(clean_patch.splitlines()) >= len(original_code.splitlines()) * 0.8:
            return clean_patch

        # If function name is provided or can be extracted from patch
        target_func = function_name
        if not target_func:
            func_match = re.search(r"(?:[a-zA-Z_][a-zA-Z0-9_* ]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{", clean_patch)
            if func_match:
                target_func = func_match.group(1)

        if target_func:
            # Replace function definition in original code using regex
            func_pattern = re.compile(
                r"(?:[a-zA-Z_][a-zA-Z0-9_* \n\t]+)\s+" + re.escape(target_func) + r"\s*\([^)]*\)\s*\{[\s\S]*?\n\s*\}",
                re.MULTILINE
            )
            if func_pattern.search(original_code):
                merged = func_pattern.sub(lambda m: clean_patch, original_code, count=1)
                
                # Header safety check: ensure <stdio.h> / <stdlib.h> if referenced in patch
                if ("snprintf" in clean_patch or "printf" in clean_patch) and "#include <stdio.h>" not in merged and "#include <cstdio>" not in merged:
                    merged = "#include <stdio.h>\n" + merged
                if ("malloc" in clean_patch or "free" in clean_patch or "NULL" in clean_patch) and "#include <stdlib.h>" not in merged and "#include <cstdlib>" not in merged:
                    merged = "#include <stdlib.h>\n" + merged
                return merged

        # Fallback: if replacement pattern wasn't matched, replace entire body or append
        return clean_patch

    def verify_patch(self, request: VerifyPatchRequest) -> VerifyPatchResponse:
        start_time = time.time()
        detected_lang = compiler_manager.detect_language(request.language, request.file_name)
        file_name = request.file_name or f"patched_source.{detected_lang}"

        # 1. Apply patch into code
        patched_code = self.apply_patch_to_code(
            original_code=request.original_code,
            patch_code=request.patch_code,
            function_name=request.function_name
        )

        # 2. Syntax Validation & LLVM IR Generation of Patched Code
        comp_res = compiler_manager.validate_and_compile(
            code=patched_code,
            language=detected_lang,
            file_name=file_name
        )

        # Check Syntax
        if not comp_res.syntax_result.is_valid:
            err_msg = "; ".join([f"Line {e.line}: {e.message}" for e in comp_res.syntax_result.errors])
            elapsed = round((time.time() - start_time) * 1000, 2)
            return VerifyPatchResponse(
                is_verified=False,
                syntax_valid=False,
                ir_generated=False,
                verified_code=patched_code,
                verification_message=f"Patch rejected: Syntax error in patched code ({err_msg})",
                remaining_issues=[f"Syntax error: {err_msg}"],
                analysis_time_ms=elapsed
            )

        # Check IR Generation
        if not comp_res.ir_result or not comp_res.ir_result.success:
            elapsed = round((time.time() - start_time) * 1000, 2)
            return VerifyPatchResponse(
                is_verified=False,
                syntax_valid=True,
                ir_generated=False,
                verified_code=patched_code,
                verification_message=f"Patch rejected: Failed to compile to LLVM IR ({comp_res.ir_result.error if comp_res.ir_result else 'Unknown IR error'})",
                remaining_issues=["LLVM IR compilation failure"],
                analysis_time_ms=elapsed
            )

        # 3. Extract new iSeVC for the Patched Code
        new_isevc = isevc_builder.build_isevc(comp_res.ir_result.ir_code, patched_code)

        # 4. Fast Semantic Verification via Gemini
        verify_prompt = f"""
Verify the following proposed security patch against the target vulnerability.

=== TARGET VULNERABILITY ===
ID: {request.vulnerability_id or 'VULN-001'}
Function: {request.function_name or 'target function'}

=== ORIGINAL VULNERABLE CODE ===
```{detected_lang}
{request.original_code}
```

=== PATCHED CODE (PROPOSED FIX) ===
```{detected_lang}
{patched_code}
```

=== NEW LLVM IR SEMANTIC CONTEXT (iSeVC) ===
{new_isevc.semantic_summary}

=== REQUIRED JSON OUTPUT ===
Return JSON with this exact schema:
{{
  "is_clean": boolean,
  "vulnerability_eliminated": boolean,
  "regressions_found": boolean,
  "verification_details": "Clear explanation of why the patch is verified secure or why issues remain.",
  "remaining_warnings": ["list of remaining issues or empty array"]
}}
"""
        try:
            ai_json = gemini_client.generate_json_response(
                prompt=verify_prompt,
                system_instruction=VERIFICATION_SYSTEM_INSTRUCTION
            )

            is_clean = ai_json.get("is_clean", False)
            vuln_eliminated = ai_json.get("vulnerability_eliminated", False)
            regressions = ai_json.get("regressions_found", False)
            details = ai_json.get("verification_details", "Verification complete.")
            warnings = ai_json.get("remaining_warnings", [])

            is_verified = is_clean and vuln_eliminated and not regressions
            elapsed = round((time.time() - start_time) * 1000, 2)

            return VerifyPatchResponse(
                is_verified=is_verified,
                syntax_valid=True,
                ir_generated=True,
                verified_code=patched_code,
                verification_message=details,
                remaining_issues=warnings if not is_verified else [],
                analysis_time_ms=elapsed
            )

        except Exception as e:
            elapsed = round((time.time() - start_time) * 1000, 2)
            return VerifyPatchResponse(
                is_verified=False,
                syntax_valid=True,
                ir_generated=True,
                verified_code=patched_code,
                verification_message=f"AI verification check error: {str(e)}",
                remaining_issues=[str(e)],
                analysis_time_ms=elapsed
            )

# Global singleton
patch_verifier = PatchVerifier()
