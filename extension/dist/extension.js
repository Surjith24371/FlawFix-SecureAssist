"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const backendClient_1 = require("./client/backendClient");
const diagnosticProvider_1 = require("./providers/diagnosticProvider");
const diffContentProvider_1 = require("./providers/diffContentProvider");
const sidebarViewProvider_1 = require("./providers/sidebarViewProvider");
const SUPPORTED_LANGUAGES = ['c', 'cpp', 'python', 'rust', 'java'];
function activate(context) {
    console.log('FlawFix SecureAssist extension activated.');
    // Initialize Services
    const backendClient = new backendClient_1.BackendClient();
    const diagnosticProvider = new diagnosticProvider_1.DiagnosticProvider();
    const diffProvider = new diffContentProvider_1.DiffContentProvider();
    // Register Diff Document Content Provider
    context.subscriptions.push(vscode.workspace.registerTextDocumentContentProvider(diffContentProvider_1.DiffContentProvider.Scheme, diffProvider));
    // Register Sidebar Webview View Provider
    const sidebarProvider = new sidebarViewProvider_1.SidebarViewProvider(context.extensionUri, backendClient, diagnosticProvider, diffProvider);
    context.subscriptions.push(vscode.window.registerWebviewViewProvider(sidebarViewProvider_1.SidebarViewProvider.viewType, sidebarProvider));
    // Register Commands
    const scanCommand = vscode.commands.registerCommand('flawfix.scanFile', async () => {
        await sidebarProvider.scanActiveDocument();
    });
    const reportCommand = vscode.commands.registerCommand('flawfix.showReport', async () => {
        vscode.window.showInformationMessage('Generating security report via FlawFix sidebar...');
        await sidebarProvider.scanActiveDocument();
    });
    const clearCommand = vscode.commands.registerCommand('flawfix.clearDiagnostics', () => {
        diagnosticProvider.clear();
        vscode.window.showInformationMessage('FlawFix security diagnostics cleared.');
    });
    context.subscriptions.push(scanCommand, reportCommand, clearCommand, diagnosticProvider);
    // Auto-scan on file save (if enabled in settings)
    const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('flawfix');
        const autoScan = config.get('autoScanOnSave', true);
        if (autoScan && SUPPORTED_LANGUAGES.includes(document.languageId)) {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor && activeEditor.document.uri.toString() === document.uri.toString()) {
                await sidebarProvider.scanActiveDocument();
            }
        }
    });
    context.subscriptions.push(onSaveListener);
}
function deactivate() { }
//# sourceMappingURL=extension.js.map