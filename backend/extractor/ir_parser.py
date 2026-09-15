import re
from typing import Dict, Tuple, List, Optional
from backend.models.isevc_schema import IRInstruction, BasicBlockContext, FunctionSemanticContext

# Common security-sensitive C/C++/Python library functions
DANGEROUS_FUNCTIONS = {
    # Unbounded buffer copy / string operations
    "strcpy", "strncpy", "strcat", "strncat", "gets", "sprintf", "vsprintf", 
    "scanf", "sscanf", "fscanf", "memcpy", "memmove", "memset",
    # Memory management
    "malloc", "calloc", "realloc", "free",
    # Command execution / Process control
    "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execvp",
    # File / Format string
    "printf", "fprintf", "vprintf", "vfprintf", "snprintf",
    # Weak Cryptographic and Insecure Hashing APIs (CWE-327 / CWE-328 / CWE-916)
    "md5", "sha1", "des", "rc4", "crypt", "hashlib.md5", "hashlib.sha1",
    "MD5_Init", "MD5_Update", "MD5_Final", "SHA1_Init", "SHA1_Update", "SHA1_Final"
}

MEMORY_OPCODES = {"alloca", "load", "store", "getelementptr", "cmpxchg", "atomicrmw"}
BRANCH_OPCODES = {"br", "switch", "indirectbr", "invoke", "ret"}

class IRParser:
    """
    Parses LLVM Intermediate Representation (.ll) text, resolves DILocation debug metadata
    to exact source code lines, and constructs structured AST/Instruction representations.
    """

    def __init__(self):
        # Regex for debug metadata: !12 = !DILocation(line: 14, column: 5, ...)
        self.di_location_regex = re.compile(r"!(\d+)\s*=\s*!DILocation\s*\(\s*line:\s*(\d+)(?:,\s*column:\s*(\d+))?")
        # Regex for source filename
        self.source_filename_regex = re.compile(r'source_filename\s*=\s*"([^"]+)"')
        # Regex for debug attachment on instruction: , !dbg !12
        self.dbg_attach_regex = re.compile(r",\s*!dbg\s*!(\d+)")
        # Regex for function definition
        self.func_def_regex = re.compile(r"^define\s+(?:dso_local\s+)?([^\s@]+)\s+@([a-zA-Z0-9_.$]+)\s*\((.*?)\)[^{]*\{", re.MULTILINE)
        # Regex for instruction assignment: %1 = opcode ... OR opcode ...
        self.instr_regex = re.compile(r"^(?:%([a-zA-Z0-9_.]+)\s*=\s*)?([a-zA-Z0-9_]+)\s*(.*)")
        # Regex for function call: call ... @func_name(
        self.call_target_regex = re.compile(r"@([a-zA-Z0-9_.$]+)\s*\(")

    def parse_debug_metadata(self, ir_text: str) -> Dict[str, Tuple[int, int]]:
        """
        Extracts all !DILocation metadata entries: id -> (line, column).
        """
        metadata: Dict[str, Tuple[int, int]] = {}
        for match in self.di_location_regex.finditer(ir_text):
            meta_id = match.group(1)
            line = int(match.group(2))
            col = int(match.group(3)) if match.group(3) else 1
            metadata[meta_id] = (line, col)
        return metadata

    def parse_instruction(self, raw_line: str, debug_map: Dict[str, Tuple[int, int]]) -> Optional[IRInstruction]:
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("}") or line.endswith(":"):
            return None

        # Resolve debug line/column
        source_line = None
        source_column = None
        dbg_match = self.dbg_attach_regex.search(line)
        if dbg_match:
            dbg_id = dbg_match.group(1)
            if dbg_id in debug_map:
                source_line, source_column = debug_map[dbg_id]

        # Strip comments and debug attachments for clean instruction parsing
        clean_line = re.sub(r",\s*!dbg\s*!\d+", "", line)
        clean_line = re.sub(r";.*$", "", clean_line).strip()

        # Parse opcode and assigned variable
        match = self.instr_regex.match(clean_line)
        if not match:
            return None

        result_var = f"%{match.group(1)}" if match.group(1) else None
        opcode = match.group(2).lower()
        rest = match.group(3).strip()

        # Extract operands / registers
        operands = re.findall(r"(%[a-zA-Z0-9_.]+|@[a-zA-Z0-9_.]+|null|true|false|-?\d+)", rest)

        is_mem = opcode in MEMORY_OPCODES
        is_branch = opcode in BRANCH_OPCODES
        is_call = opcode in ("call", "invoke", "tail call")
        is_ptr = "ptr" in rest or "*" in rest or opcode in ("getelementptr", "alloca")

        called_func = None
        is_sensitive = False
        security_tag = None

        if is_call:
            call_match = self.call_target_regex.search(rest)
            if call_match:
                called_func = call_match.group(1)
                # Normalize names like llvm.memcpy -> memcpy, hashlib.md5 -> md5
                norm_name = called_func.split(".")[-1].lower()
                func_lower = called_func.lower()
                if (called_func in DANGEROUS_FUNCTIONS or 
                    norm_name in DANGEROUS_FUNCTIONS or
                    any(k in func_lower for k in ("md5", "sha1", "des", "rc4", "crypt"))):
                    is_sensitive = True
                    security_tag = f"dangerous_call:{norm_name}"

        elif opcode == "getelementptr":
            is_sensitive = True
            security_tag = "pointer_arithmetic_or_array_indexing"

        elif opcode == "alloca" and ("[" in rest or "array" in rest.lower() or "ptr" in rest):
            is_sensitive = True
            security_tag = "buffer_or_pointer_allocation"

        return IRInstruction(
            raw_text=line,
            opcode=opcode,
            result_var=result_var,
            operands=operands,
            source_line=source_line,
            source_column=source_column,
            is_memory_op=is_mem,
            is_pointer_op=is_ptr,
            is_call=is_call,
            called_function=called_func,
            is_branch=is_branch,
            is_security_sensitive=is_sensitive,
            security_tag=security_tag
        )

    def parse_functions(self, ir_text: str) -> List[FunctionSemanticContext]:
        """
        Extracts all function definitions and their basic blocks.
        """
        debug_map = self.parse_debug_metadata(ir_text)
        user_declared_funcs = set(re.findall(r'distinct\s+!DISubprogram\s*\(\s*name:\s*"([^"]+)"', ir_text))
        functions: List[FunctionSemanticContext] = []

        # Find all function blocks
        lines = ir_text.splitlines()
        in_function = False
        current_func_name = ""
        current_return_type = ""
        current_args = []
        current_blocks: List[BasicBlockContext] = []
        current_bb_label = "entry"
        current_bb_instrs: List[IRInstruction] = []

        for line in lines:
            line_str = line.strip()

            # Start of function
            if line_str.startswith("define ") and "{" in line_str:
                in_function = True
                # Match: define [linkage] [preemption] [visibility] [cconv] [ret_type] @func_name(args)
                func_match = re.search(r"define\s+.*?([^\s@]+)\s+@([a-zA-Z0-9_.$]+)\s*\((.*?)\)", line_str)
                if func_match:
                    current_return_type = func_match.group(1)
                    current_func_name = func_match.group(2)
                    current_args = [a.strip() for a in func_match.group(3).split(",") if a.strip()]
                else:
                    current_func_name = "unknown_function"
                    current_return_type = "void"
                    current_args = []

                current_blocks = []
                current_bb_label = "entry"
                current_bb_instrs = []
                continue

            # End of function
            if in_function and line_str == "}":
                if current_bb_instrs or current_blocks:
                    # Flush last block
                    lines_covered = [i.source_line for i in current_bb_instrs if i.source_line]
                    current_blocks.append(BasicBlockContext(
                        label=current_bb_label,
                        instructions=current_bb_instrs,
                        source_lines=sorted(list(set(lines_covered)))
                    ))

                # Aggregate function-level metrics
                all_covered_lines = set()
                allocs = []
                ptrs = []
                calls = []

                for bb in current_blocks:
                    all_covered_lines.update(bb.source_lines)
                    for instr in bb.instructions:
                        if instr.opcode == "alloca":
                            allocs.append({
                                "var": instr.result_var,
                                "source_line": instr.source_line,
                                "raw": instr.raw_text
                            })
                        if instr.is_pointer_op or instr.opcode == "getelementptr":
                            ptrs.append({
                                "opcode": instr.opcode,
                                "target": instr.result_var,
                                "source_line": instr.source_line
                            })
                        if instr.is_call and instr.called_function:
                            calls.append({
                                "function": instr.called_function,
                                "source_line": instr.source_line,
                                "is_dangerous": instr.is_security_sensitive,
                                "tag": instr.security_tag
                            })

                functions.append(FunctionSemanticContext(
                    function_name=current_func_name,
                    return_type=current_return_type,
                    arguments=current_args,
                    basic_blocks=current_blocks,
                    memory_allocations=allocs,
                    pointer_operations=ptrs,
                    critical_calls=calls,
                    source_lines_covered=sorted(list(all_covered_lines))
                ))

                in_function = False
                current_blocks = []
                current_bb_instrs = []
                continue

            if in_function:
                # Basic block label (e.g. `entry:` or `if.then:`)
                if line_str.endswith(":") and not line_str.startswith(";"):
                    if current_bb_instrs:
                        lines_covered = [i.source_line for i in current_bb_instrs if i.source_line]
                        current_blocks.append(BasicBlockContext(
                            label=current_bb_label,
                            instructions=current_bb_instrs,
                            source_lines=sorted(list(set(lines_covered)))
                        ))
                    current_bb_label = line_str.rstrip(":")
                    current_bb_instrs = []
                    continue

                parsed = self.parse_instruction(line_str, debug_map)
                if parsed:
                    current_bb_instrs.append(parsed)

        return functions
