import re
from typing import List, Optional
from backend.models.isevc_schema import (
    iSeVCResult,
    FunctionSemanticContext,
    IRInstruction
)
from backend.extractor.ir_parser import IRParser
from backend.extractor.cfg_builder import CFGBuilder

class iSeVCBuilder:
    """
    Intermediate Semantic Vulnerability Context (iSeVC) Builder.
    Transforms raw LLVM IR into structured, semantic contexts for LLM vulnerability analysis.
    Performs context pruning to eliminate compiler boilerplate while preserving all security semantics.
    """

    def __init__(self):
        self.parser = IRParser()
        self.cfg_builder = CFGBuilder()

    def build_isevc(self, ir_text: str, source_code: Optional[str] = None) -> iSeVCResult:
        if not ir_text or not ir_text.strip():
            return iSeVCResult(
                success=False,
                error="Empty or invalid LLVM IR text provided"
            )

        raw_size = len(ir_text.encode("utf-8"))

        # Step 1: Parse functions & instructions
        raw_functions = self.parser.parse_functions(ir_text)

        # Step 2: Early prune of compiler internal & stdlib inline functions before CFG building
        STDLIB_INLINES = {
            "sprintf", "printf", "fprintf", "snprintf", "vprintf", "vsprintf", "vsnprintf",
            "sscanf", "scanf", "fscanf", "__local_stdio_printf_options", "__local_stdio_scanf_options"
        }
        
        target_functions = [
            f for f in raw_functions 
            if f.function_name not in STDLIB_INLINES 
            and not f.function_name.startswith("__") 
            and not f.function_name.startswith("llvm.")
            and not (f.function_name.startswith("_") and f.function_name not in ("_main", "_start"))
        ]
        if not target_functions:
            target_functions = raw_functions

        enhanced_functions: List[FunctionSemanticContext] = []
        all_data_flows = []

        for func in target_functions:
            func_cfg = self.cfg_builder.build_cfg(func)
            flows = self.cfg_builder.trace_data_dependencies(func_cfg)
            all_data_flows.extend(flows)
            enhanced_functions.append(func_cfg)

        # Step 3: Extract global symbols / strings
        globals_list = []
        for line in ir_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("@") and ("=" in line_s) and ("global" in line_s or "constant" in line_s):
                globals_list.append(re.sub(r",\s*!dbg\s*!\d+", "", line_s))

        # Step 4: Synthesize the Pruned Semantic Summary (iSeVC Prompt Context)
        summary_sections = [
            "=== INTERMEDIATE SEMANTIC VULNERABILITY CONTEXT (iSeVC) ===",
            "Language-Independent Program Semantic Behavior & Control/Data-Flow Representation\n"
        ]

        if globals_list:
            summary_sections.append("--- GLOBAL SYMBOLS & CONSTANTS ---")
            for g in globals_list[:10]:  # limit to top 10 global constants
                summary_sections.append(f"  {g}")
            summary_sections.append("")

        user_functions = enhanced_functions

        for func in user_functions:
            summary_sections.append(f"--- FUNCTION: @{func.function_name} ({func.return_type}) ---")
            summary_sections.append(f"  Source Lines Covered: {func.source_lines_covered}")

            if func.memory_allocations:
                summary_sections.append("  [Memory Allocations / Buffers]:")
                for alloc in func.memory_allocations:
                    line_info = f"Line {alloc['source_line']}" if alloc['source_line'] else "Unknown Line"
                    summary_sections.append(f"    - {alloc['raw']} (Source: {line_info})")

            if func.critical_calls:
                summary_sections.append("  [Security-Sensitive Calls]:")
                for c in func.critical_calls:
                    line_info = f"Line {c['source_line']}" if c['source_line'] else "Unknown Line"
                    tag_info = f" [TAG: {c['tag']}]" if c['tag'] else ""
                    summary_sections.append(f"    - Call to @{c['function']}() at {line_info}{tag_info}")

            summary_sections.append("  [Control Flow & Block Sequence]:")
            for bb in func.basic_blocks:
                succ_str = f" -> Next Blocks: {bb.successors}" if bb.successors else " -> (Exit/Ret)"
                pred_str = f" <- From: {bb.predecessors}" if bb.predecessors else ""
                summary_sections.append(f"    Block '{bb.label}' (Lines {bb.source_lines}){pred_str}{succ_str}:")
                for instr in bb.instructions:
                    line_str = f"[L{instr.source_line}] " if instr.source_line else ""
                    tag_str = f" <⚠️ {instr.security_tag}>" if instr.is_security_sensitive else ""
                    # Omit non-essential verbose annotations
                    summary_sections.append(f"      {line_str}{instr.opcode} {', '.join(instr.operands)}{tag_str}")
            summary_sections.append("")

        if all_data_flows:
            summary_sections.append("--- DATA FLOW DEPENDENCY TRACES (Def-Use Chains into Sensitive Sites) ---")
            for flow in all_data_flows:
                src_line = f"Line {flow['source_line']}" if flow['source_line'] else "Unknown"
                summary_sections.append(f"  Target: {flow['sensitive_instruction']} ({src_line})")
                for origin in flow.get("origin_definitions", []):
                    summary_sections.append(f"    <- Origin: {origin['origin_opcode']} {origin['var']} at Line {origin['origin_line']}: '{origin['origin_raw']}'")
            summary_sections.append("")

        summary_text = "\n".join(summary_sections)
        pruned_size = len(summary_text.encode("utf-8"))

        reduction_pct = round(((raw_size - pruned_size) / raw_size * 100), 2) if raw_size > 0 else 0.0

        return iSeVCResult(
            success=True,
            functions=enhanced_functions,
            global_symbols=globals_list,
            semantic_summary=summary_text,
            raw_ir_size_bytes=raw_size,
            pruned_size_bytes=pruned_size,
            reduction_percentage=reduction_pct
        )

# Global singleton instance
isevc_builder = iSeVCBuilder()
