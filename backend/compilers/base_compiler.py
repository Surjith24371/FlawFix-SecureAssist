from abc import ABC, abstractmethod
from typing import Optional
from backend.models.schema import SyntaxValidationResult, LLVMIRResult

class BaseCompiler(ABC):
    """
    Abstract base class for all language-specific compilers and syntax checkers.
    """

    def __init__(self, language_name: str):
        self.language_name = language_name

    @abstractmethod
    def validate_syntax(self, code: str, file_name: Optional[str] = None) -> SyntaxValidationResult:
        """
        Validates source code syntax. Returns structured syntax errors and warnings.
        Must NOT generate LLVM IR if syntax is invalid.
        """
        pass

    @abstractmethod
    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None, already_validated: bool = False) -> LLVMIRResult:
        """
        Generates LLVM Intermediate Representation (.ll) text from syntactically valid code.
        If already_validated is True, skips redundant syntax check to optimize performance.
        """
        pass

    def compile_pipeline(self, code: str, file_name: Optional[str] = None) -> tuple[SyntaxValidationResult, Optional[LLVMIRResult]]:
        """
        Executes an optimized compilation pipeline.
        Default implementation performs 2-step validation and compilation.
        Compilers can override this method to perform a high-performance single-pass compilation.
        """
        syntax_res = self.validate_syntax(code, file_name)
        if not syntax_res.is_valid:
            return syntax_res, None
        ir_res = self.generate_llvm_ir(code, file_name, already_validated=True)
        return syntax_res, ir_res

