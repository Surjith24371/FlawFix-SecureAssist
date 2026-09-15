import * as vscode from 'vscode';
import { BackendClient, FullAnalysisResponse } from '../client/backendClient';
import { DiagnosticProvider } from './diagnosticProvider';
import { DiffContentProvider } from './diffContentProvider';

export class SidebarViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'flawfix.sidebar';
    private _view?: vscode.WebviewView;
    private latestAnalysis?: FullAnalysisResponse;
    private verifiedPatches: Array<{ vulnerability_id: string; status: string; message: string }> = [];

    constructor(
        private readonly extensionUri: vscode.Uri,
        private readonly backendClient: BackendClient,
        private readonly diagnosticProvider: DiagnosticProvider,
        private readonly diffProvider: DiffContentProvider
    ) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this.extensionUri]
        };

        webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);

        webviewView.webview.onDidReceiveMessage(async message => {
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
            }
        });

        if (this.latestAnalysis) {
            this.sendAnalysisToWebview(this.latestAnalysis);
        }
    }

    public async scanActiveDocument(): Promise<FullAnalysisResponse | undefined> {
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
            } else if (response.analysis_result?.is_vulnerable) {
                vscode.window.showWarningMessage(
                    `🛡️ FlawFix detected ${response.analysis_result.total_vulnerabilities} security vulnerabilities in ${fileName}. Check the sidebar for fixes.`
                );
            } else if (response.analysis_result && !response.analysis_result.is_vulnerable) {
                vscode.window.showInformationMessage(
                    `🛡️ FlawFix Security Audit: 0 vulnerabilities found in ${fileName}. Code is clean!`
                );
            }

            return response;
        } catch (error: any) {
            const errMsg = error.response?.data?.error || error.message || 'Analysis failed.';
            this.sendAnalysisError(errMsg);
            vscode.window.showErrorMessage(`FlawFix Scan Error: ${errMsg}`);
            return undefined;
        }
    }

    private async handlePreviewPatch(patchCode: string, vulnId: string) {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const originalUri = editor.document.uri;
        await this.diffProvider.showDiff(originalUri, patchCode, vulnId);
    }

    private async handleApplyAndVerifyPatch(patchCode: string, functionName: string, vulnId: string) {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor open to apply patch.');
            return;
        }

        const document = editor.document;
        const originalCode = document.getText();
        const language = document.languageId;

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `FlawFix: Verifying and applying secure patch for ${vulnId}...`,
            cancellable: false
        }, async () => {
            try {
                const verifyRes = await this.backendClient.verifyPatch(
                    originalCode,
                    patchCode,
                    functionName,
                    language,
                    vulnId
                );

                if (verifyRes.is_verified) {
                    // Apply verified code to editor document
                    const fullRange = new vscode.Range(
                        document.positionAt(0),
                        document.positionAt(originalCode.length)
                    );
                    await editor.edit(editBuilder => {
                        editBuilder.replace(fullRange, verifyRes.verified_code);
                    });

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
                } else {
                    this.notifyPatchApplied(vulnId, false, verifyRes.verification_message);
                    vscode.window.showErrorMessage(`⚠️ Patch verification failed: ${verifyRes.verification_message}`);
                }
            } catch (err: any) {
                vscode.window.showErrorMessage(`Error during patch verification: ${err.message}`);
            }
        });
    }

    private async handleGenerateReport() {
        const editor = vscode.window.activeTextEditor;
        if (!this.latestAnalysis || !this.latestAnalysis.analysis_result) {
            vscode.window.showWarningMessage('Please run a security scan first before generating a report.');
            return;
        }

        const fileName = editor?.document.fileName.split(/[\\/]/).pop() || 'project_file';
        const language = this.latestAnalysis.language || 'c';

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'FlawFix: Generating PDF Security Audit Report...',
            cancellable: false
        }, async () => {
            try {
                const reportRes = await this.backendClient.generateReport(
                    'FlawFix Workspace',
                    fileName,
                    language,
                    this.latestAnalysis!.analysis_result!,
                    this.verifiedPatches
                );

                const downloadUrl = this.backendClient.getReportDownloadUrl(reportRes.download_url);
                vscode.window.showInformationMessage(
                    `✓ Report generated: ${reportRes.file_name} (${reportRes.file_size_bytes} bytes)`,
                    'Open Report PDF'
                ).then(selection => {
                    if (selection === 'Open Report PDF') {
                        vscode.env.openExternal(vscode.Uri.parse(downloadUrl));
                    }
                });
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to generate report: ${err.message}`);
            }
        });
    }

    public sendAnalysisStarted() {
        if (this._view) {
            this._view.webview.postMessage({ type: 'analysisStarted' });
        }
    }

    public sendAnalysisToWebview(data: FullAnalysisResponse) {
        if (this._view) {
            this._view.webview.postMessage({ type: 'analysisComplete', data });
        }
    }

    public sendAnalysisError(error: string) {
        if (this._view) {
            this._view.webview.postMessage({ type: 'analysisError', error });
        }
    }

    public notifyPatchApplied(vulnId: string, verified: boolean, message: string) {
        if (this._view) {
            this._view.webview.postMessage({ type: 'patchApplied', vulnId, verified, message });
        }
    }

    private getHtmlForWebview(webview: vscode.Webview): string {
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
