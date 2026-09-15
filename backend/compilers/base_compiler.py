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
    def generate_llvm_ir(self, code: str, file_name: Optional[str] = None) -> LLVMIRResult:
        """
        Generates LLVM Intermediate Representation (.ll) text from syntactically valid code.
        """
        pass
