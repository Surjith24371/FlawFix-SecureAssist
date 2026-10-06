"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DiagnosticProvider = void 0;
const vscode = require("vscode");
class DiagnosticProvider {
    diagnosticCollection;
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('flawfix');
    }
    updateDiagnostics(document, analysis) {
        const diagnostics = [];
        // 1. Syntax Errors
        if (!analysis.syntax_result.is_valid && analysis.syntax_result.errors) {
            for (const err of analysis.syntax_result.errors) {
                const lineIndex = Math.max(0, err.line - 1);
                const colIndex = Math.max(0, err.column - 1);
                const line = document.lineAt(Math.min(lineIndex, document.lineCount - 1));
                const range = new vscode.Range(lineIndex, colIndex, lineIndex, line.text.length);
                const typeStr = err.error_type ? `[${err.error_type}] ` : '';
                const explStr = err.explanation ? `\n\nExplanation: ${err.explanation}` : '';
                const diagnostic = new vscode.Diagnostic(range, `[FlawFix Syntax Error] ${typeStr}${err.message}${explStr}`, vscode.DiagnosticSeverity.Error);
                diagnostic.source = err.source || 'FlawFix Compiler';
                diagnostics.push(diagnostic);
            }
        }
        // 2. Security Vulnerabilities
        if (analysis.analysis_result && analysis.analysis_result.vulnerabilities) {
            for (const vuln of analysis.analysis_result.vulnerabilities) {
                const severity = this.mapSeverity(vuln.severity);
                // If affected lines are specified
                const lines = vuln.affected_lines && vuln.affected_lines.length > 0
                    ? vuln.affected_lines
                    : [1];
                for (const lineNum of lines) {
                    const lineIndex = Math.max(0, lineNum - 1);
                    const line = document.lineAt(Math.min(lineIndex, document.lineCount - 1));
                    const range = new vscode.Range(lineIndex, 0, lineIndex, line.text.length);
                    const message = `🛡️ [${vuln.severity.toUpperCase()}] ${vuln.title}\nCWE: ${vuln.cwe_id}\n\nRoot Cause: ${vuln.root_cause}\n\nRemediation: ${vuln.recommendation}`;
                    const diagnostic = new vscode.Diagnostic(range, message, severity);
                    diagnostic.source = 'FlawFix SecureAssist';
                    diagnostic.code = vuln.cwe_id;
                    diagnostics.push(diagnostic);
                }
            }
        }
        this.diagnosticCollection.set(document.uri, diagnostics);
    }
    clear(documentUri) {
        if (documentUri) {
            this.diagnosticCollection.delete(documentUri);
        }
        else {
            this.diagnosticCollection.clear();
        }
    }
    mapSeverity(sevStr) {
        switch (sevStr.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }
    dispose() {
        this.diagnosticCollection.dispose();
    }
}
exports.DiagnosticProvider = DiagnosticProvider;
//# sourceMappingURL=diagnosticProvider.js.map