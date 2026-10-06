import time
from typing import Optional
from backend.models.verification_schema import VerifyPatchRequest, VerifyPatchResponse
from backend.compilers.compiler_manager import compiler_manager
from backend.extractor.isevc_builder import isevc_builder
from backend.ai.gemini_client import gemini_client
from backend.verifier.patch_replacer import FunctionPatchReplacer

VERIFICATION_SYSTEM_INSTRUCTION = """
You are a Principal Compiler and Code Verification Security Engineer.
Your task is to verify whether a proposed security patch eliminates a specific detected vulnerability
WITHOUT introducing syntax errors, semantic regressions, or new security vulnerabilities.

CRITICAL EVALUATION CRITERIA:
1. "vulnerability_eliminated": Set to TRUE if the target security flaw (e.g. buffer overflow, SQL injection, format string) has been effectively mitigated or prevented.
2. "regressions_found": Set to TRUE ONLY if the patch introduces severe breaking changes, broken execution paths, syntax bugs, or new security vulnerabilities. Minor stylistic suggestions or optional optimizations are NOT regressions.
3. "is_clean": Set to TRUE if the patch is safe, compilable, and acceptable for production.
4. "remaining_warnings": List any optional best-practice advice or non-blocking recommendations. If none, return an empty array [].
5. Output STRICT JSON only.
"""

class PatchVerifier:
    """
    Automated Dual-Engine Patch Verification Subsystem (SRS Modules 5.3.7 & 5.3.8).
    Applies patches using grammar-aware function boundary replacement, compiles patched code
    to LLVM IR, extracts new iSeVCs, and verifies complete vulnerability elimination.
    """

    def apply_patch_to_code(
        self,
        original_code: str,
        patch_code: str,
        function_name: Optional[str] = None,
        language: str = "c"
    ) -> str:
        """
        Integrates a function-level patch into the original source code using FunctionPatchReplacer.
        Preserves indentation, comments, surrounding code, and nested blocks.
        """
        return FunctionPatchReplacer.apply_patch(
            original_code=original_code,
            patch_code=patch_code,
            function_name=function_name,
            language=language
        )

    def verify_patch(self, request: VerifyPatchRequest) -> VerifyPatchResponse:
        start_time = time.time()
        detected_lang = compiler_manager.detect_language(
            language=request.language,
            file_name=request.file_name,
            code=request.original_code or request.patch_code
        )
        file_name = request.file_name or f"patched_source.{detected_lang}"

        # 1. Apply patch into complete source code using grammar-aware boundary replacement
        patched_code = self.apply_patch_to_code(
            original_code=request.original_code,
            patch_code=request.patch_code,
            function_name=request.function_name,
            language=detected_lang
        )

        # 2. Syntax Validation & LLVM IR Generation of Patched Complete Source (bypass cache for freshly patched code)
        comp_res = compiler_manager.validate_and_compile(
            code=patched_code,
            language=detected_lang,
            file_name=file_name,
            use_cache=False
        )

        # Check Syntax Gate
        if not comp_res.syntax_result.is_valid:
            err_details = "; ".join([
                f"Line {e.line}, Col {e.column}: [{e.error_type or 'SyntaxError'}] {e.message}"
                for e in comp_res.syntax_result.errors
            ])
            elapsed = round((time.time() - start_time) * 1000, 2)
            return VerifyPatchResponse(
                is_verified=False,
                syntax_valid=False,
                ir_generated=False,
                verified_code=patched_code,
                verification_message=f"Patch rejected: Syntax error in patched code ({err_details})",
                remaining_issues=[f"Syntax error: {err_details}"],
                analysis_time_ms=elapsed
            )

        # Check LLVM IR Generation Gate
        if not comp_res.ir_result or not comp_res.ir_result.success:
            ir_err = comp_res.ir_result.error if comp_res.ir_result else "Unknown IR generation error"
            if "timed out" in ir_err.lower():
                ir_err = "LLVM IR generation timed out while processing the source code. Security analysis could not be completed."
            elapsed = round((time.time() - start_time) * 1000, 2)
            return VerifyPatchResponse(
                is_verified=False,
                syntax_valid=True,
                ir_generated=False,
                verified_code=patched_code,
                verification_message=f"Patch rejected: {ir_err}",
                remaining_issues=[ir_err],
                analysis_time_ms=elapsed
            )

        # 3. Extract new iSeVC for the Patched Complete Code
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

=== COMPLETE PATCHED SOURCE CODE ===
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

            # Verified if vulnerability is eliminated and no breaking regressions exist
            is_verified = (vuln_eliminated and not regressions) or (is_clean and not regressions)
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
