import re
from typing import List, Dict, Any
from backend.models.isevc_schema import FunctionSemanticContext, BasicBlockContext, IRInstruction

class CFGBuilder:
    """
    Constructs Control Flow Graph (CFG) edges (predecessors/successors) and
    analyzes Data Flow dependencies (def-use chains) for LLVM IR basic blocks.
    """

    def build_cfg(self, function_ctx: FunctionSemanticContext) -> FunctionSemanticContext:
        """
        Populates predecessor and successor links across all basic blocks in a function.
        """
        block_map: Dict[str, BasicBlockContext] = {bb.label: bb for bb in function_ctx.basic_blocks}

        # Clear existing edges
        for bb in function_ctx.basic_blocks:
            bb.predecessors = []
            bb.successors = []

        for i, bb in enumerate(function_ctx.basic_blocks):
            if not bb.instructions:
                # Fallthrough to next block if empty
                if i + 1 < len(function_ctx.basic_blocks):
                    next_label = function_ctx.basic_blocks[i + 1].label
                    bb.successors.append(next_label)
                continue

            last_instr = bb.instructions[-1]
            raw = last_instr.raw_text

            if last_instr.opcode == "br":
                # Matches: br label %label_name OR br i1 %cond, label %true_label, label %false_label
                targets = re.findall(r"label\s+%([a-zA-Z0-9_.]+)", raw)
                for t in targets:
                    if t not in bb.successors:
                        bb.successors.append(t)
            elif last_instr.opcode == "switch":
                targets = re.findall(r"label\s+%([a-zA-Z0-9_.]+)", raw)
                for t in targets:
                    if t not in bb.successors:
                        bb.successors.append(t)
            elif last_instr.opcode != "ret" and last_instr.opcode != "unreachable":
                # Implicit fallthrough
                if i + 1 < len(function_ctx.basic_blocks):
                    next_label = function_ctx.basic_blocks[i + 1].label
                    if next_label not in bb.successors:
                        bb.successors.append(next_label)

        # Compute predecessors from successors
        for bb in function_ctx.basic_blocks:
            for succ_label in bb.successors:
                if succ_label in block_map:
                    if bb.label not in block_map[succ_label].predecessors:
                        block_map[succ_label].predecessors.append(bb.label)

        return function_ctx

    def trace_data_dependencies(self, function_ctx: FunctionSemanticContext) -> List[Dict[str, Any]]:
        """
        Finds def-use data flows, especially tracing buffer pointers to dangerous calls.
        """
        flows = []
        def_map: Dict[str, IRInstruction] = {}

        # Record variable definitions
        for bb in function_ctx.basic_blocks:
            for instr in bb.instructions:
                if instr.result_var:
                    def_map[instr.result_var] = instr

        # Track usage in security sensitive calls
        for bb in function_ctx.basic_blocks:
            for instr in bb.instructions:
                if instr.is_security_sensitive:
                    trace = {
                        "sensitive_instruction": instr.raw_text,
                        "source_line": instr.source_line,
                        "tag": instr.security_tag,
                        "origin_definitions": []
                    }
                    for operand in instr.operands:
                        if operand in def_map:
                            origin = def_map[operand]
                            trace["origin_definitions"].append({
                                "var": operand,
                                "origin_opcode": origin.opcode,
                                "origin_line": origin.source_line,
                                "origin_raw": origin.raw_text
                            })
                    flows.append(trace)

        return flows
