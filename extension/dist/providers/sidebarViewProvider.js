"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SidebarViewProvider = void 0;
const vscode = require("vscode");
class SidebarViewProvider {
    extensionUri;
    backendClient;
    diagnosticProvider;
    diffProvider;
    static viewType = 'flawfix.sidebar';
    _view;
    latestAnalysis;
    verifiedPatches = [];
    constructor(extensionUri, backendClient, diagnosticProvider, diffProvider) {
        this.extensionUri = extensionUri;
        this.backendClient = backendClient;
        this.diagnosticProvider = diagnosticProvider;
        this.diffProvider = diffProvider;
    }
    resolveWebviewView(webviewView, context, _token) {
        this._view = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this.extensionUri]
        };
        webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);
        webviewView.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'scanFile':
                    await this.scanActiveDocument();
                    break;
                case 'previewPatch':
                    await this.handlePreviewPatch(message.patchCode, message.vulnId);
                    break;
                case 'applyAndVerifyPatch':
                    await this.handleApplyAndVerifyPatch(message.patchCode, message.functionName, message.vulnId);
                    break;
                case 'generateReport':
                    await this.handleGenerateReport();
                    break;
                case 'goToLine':
                    const activeEd = vscode.window.activeTextEditor;
                    if (activeEd) {
                        const targetLine = Math.max(0, (message.line || 1) - 1);
                        const targetCol = Math.max(0, (message.column || 1) - 1);
                        const targetPos = new vscode.Position(targetLine, targetCol);
                        activeEd.selection = new vscode.Selection(targetPos, targetPos);
                        activeEd.revealRange(new vscode.Range(targetPos, targetPos), vscode.TextEditorRevealType.InCenter);
                    }
                    break;
            }
        });
        if (this.latestAnalysis) {
            this.sendAnalysisToWebview(this.latestAnalysis);
        }
    }
    async scanActiveDocument() {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('FlawFix: No active source file open to scan.');
            return undefined;
        }
        const document = editor.document;
        const code = document.getText();
        const languageId = document.languageId;
        const fileName = document.fileName.split(/[\\/]/).pop() || 'source_code';
        this.sendAnalysisStarted();
        try {
            const isBackendAlive = await this.backendClient.checkHealth();
            if (!isBackendAlive) {
                const msg = 'FlawFix Backend service is not running on http://127.0.0.1:8000. Please start the backend with `python backend/app.py`.';
                vscode.window.showErrorMessage(msg);
                this.sendAnalysisError(msg);
                return undefined;
            }
            const response = await this.backendClient.analyzeFile(code, languageId, fileName);
            this.latestAnalysis = response;
            this.diagnosticProvider.updateDiagnostics(document, response);
            this.sendAnalysisToWebview(response);
            if (response.error) {
                vscode.window.showErrorMessage(`FlawFix Security Analysis Error: ${response.error}`);
                this.sendAnalysisError(response.error);
            }
            else if (response.analysis_result?.is_vulnerable) {
                vscode.window.showWarningMessage(`🛡️ FlawFix detected ${response.analysis_result.total_vulnerabilities} security vulnerabilities in ${fileName}. Check the sidebar for fixes.`);
            }
            else if (response.analysis_result && !response.analysis_result.is_vulnerable) {
                vscode.window.showInformationMessage(`🛡️ FlawFix Security Audit: 0 vulnerabilities found in ${fileName}. Code is clean!`);
            }
            return response;
        }
        catch (error) {
            const errMsg = error.response?.data?.error || error.message || 'Analysis failed.';
            this.sendAnalysisError(errMsg);
            vscode.window.showErrorMessage(`FlawFix Scan Error: ${errMsg}`);
            return undefined;
        }
    }
    async handlePreviewPatch(patchCode, vulnId) {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        const originalUri = editor.document.uri;
        await this.diffProvider.showDiff(originalUri, patchCode, vulnId);
    }
    async handleApplyAndVerifyPatch(patchCode, functionName, vulnId) {
        let editor = vscode.window.activeTextEditor;
        // If the active editor is the diff preview (flawfix-patch://), locate the underlying file editor
        if (editor && editor.document.uri.scheme === 'flawfix-patch') {
            const visible = vscode.window.visibleTextEditors.find(e => e.document.uri.scheme === 'file');
            if (visible) {
                editor = visible;
            }
        }
        if (!editor) {
            vscode.window.showErrorMessage('No active editor open to apply patch.');
            return;
        }
        const document = editor.document;
        const originalCode = document.getText();
        // Resolve accurate language and filename
        let language = document.languageId;
        if ((!language || language === 'plaintext') && this.latestAnalysis && this.latestAnalysis.language) {
            language = this.latestAnalysis.language;
        }
        const fileName = (this.latestAnalysis && this.latestAnalysis.file_name)
            ? this.latestAnalysis.file_name
            : (document.fileName.split(/[\\/]/).pop() || 'source_code');
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `FlawFix: Verifying and applying secure patch for ${vulnId}...`,
            cancellable: false
        }, async () => {
            try {
                const verifyRes = await this.backendClient.verifyPatch(originalCode, patchCode, functionName, language, vulnId, fileName);
                if (verifyRes.is_verified) {
                    // Apply verified code to editor document via WorkspaceEdit for maximum reliability
                    const edit = new vscode.WorkspaceEdit();
                    const fullRange = new vscode.Range(document.positionAt(0), document.positionAt(originalCode.length));
                    edit.replace(document.uri, fullRange, verifyRes.verified_code);
                    const applied = await vscode.workspace.applyEdit(edit);
                    if (!applied) {
                        await editor.edit(editBuilder => {
                            editBuilder.replace(fullRange, verifyRes.verified_code);
                        });
                    }
                    await document.save();
                    this.verifiedPatches.push({
                        vulnerability_id: vulnId,
                        status: 'VERIFIED',
                        message: verifyRes.verification_message
                    });
                    this.notifyPatchApplied(vulnId, true, verifyRes.verification_message);
                    vscode.window.showInformationMessage(`✓ Patch verified and applied successfully! (${verifyRes.analysis_time_ms} ms)`);
                    // Re-run scan to refresh diagnostics
                    await this.scanActiveDocument();
                }
                else {
                    this.notifyPatchApplied(vulnId, false, verifyRes.verification_message);
                    vscode.window.showErrorMessage(`⚠️ Patch verification failed: ${verifyRes.verification_message}`);
                }
            }
            catch (err) {
                vscode.window.showErrorMessage(`Error during patch verification: ${err.message}`);
            }
        });
    }
    async handleGenerateReport() {
        const editor = vscode.window.activeTextEditor;
        if (!this.latestAnalysis || !this.latestAnalysis.analysis_result) {
            vscode.window.showWarningMessage('Please run a security scan first before generating a report.');
            return;
        }
        const fileName = editor?.document.fileName.split(/[\\/]/).pop() || 'project_file';
        const language = this.latestAnalysis.language || 'c';
        const originalCode = editor ? editor.document.getText() : undefined;
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'FlawFix: Generating PDF Security Audit Report...',
            cancellable: false
        }, async () => {
            try {
                const reportRes = await this.backendClient.generateReport('FlawFix Workspace', fileName, language, this.latestAnalysis.analysis_result, this.verifiedPatches, originalCode);
                const downloadUrl = this.backendClient.getReportDownloadUrl(reportRes.download_url);
                vscode.window.showInformationMessage(`✓ Report generated: ${reportRes.file_name} (${reportRes.file_size_bytes} bytes)`, 'Open Report PDF').then(selection => {
                    if (selection === 'Open Report PDF') {
                        vscode.env.openExternal(vscode.Uri.parse(downloadUrl));
                    }
                });
            }
            catch (err) {
                vscode.window.showErrorMessage(`Failed to generate report: ${err.message}`);
            }
        });
    }
    sendAnalysisStarted() {
        if (this._view) {
            this._view.webview.postMessage({ type: 'analysisStarted' });
        }
    }
    sendAnalysisToWebview(data) {
        if (this._view) {
            this._view.webview.postMessage({ type: 'analysisComplete', data });
        }
    }
    sendAnalysisError(error) {
        if (this._view) {
            this._view.webview.postMessage({ type: 'analysisError', error });
        }
    }
    notifyPatchApplied(vulnId, verified, message) {
        if (this._view) {
            this._view.webview.postMessage({ type: 'patchApplied', vulnId, verified, message });
        }
    }
    getHtmlForWebview(webview) {
        const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'media', 'sidebar.css'));
        const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'media', 'sidebar.js'));
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="${styleUri}" rel="stylesheet">
    <title>FlawFix SecureAssist</title>
</head>
<body>
    <div class="header-container">
        <div class="header-title">
            <span>🛡️</span>
            <span>FlawFix SecureAssist</span>
        </div>
        <button id="scan-btn" class="btn-primary">
            <span>⚡ Scan Active File</span>
        </button>
        <button id="report-btn" class="btn-secondary" style="display: none;">
            <span>📄 Export Security PDF Report</span>
        </button>
    </div>

    <div id="status-container" style="display: none;"></div>
    <div id="scorecard-container" style="display: none;"></div>
    <div id="vuln-list" class="vuln-list"></div>
    <div id="optimizations-container"></div>

    <script src="${scriptUri}"></script>
</body>
</html>`;
    }
}
exports.SidebarViewProvider = SidebarViewProvider;
//# sourceMappingURL=sidebarViewProvider.js.map