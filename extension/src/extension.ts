import * as vscode from 'vscode';
import { BackendClient } from './client/backendClient';
import { DiagnosticProvider } from './providers/diagnosticProvider';
import { DiffContentProvider } from './providers/diffContentProvider';
import { SidebarViewProvider } from './providers/sidebarViewProvider';

const SUPPORTED_LANGUAGES = ['c', 'cpp', 'python', 'rust', 'java'];

export function activate(context: vscode.ExtensionContext) {
    console.log('FlawFix SecureAssist extension activated.');

    // Initialize Services
    const backendClient = new BackendClient();
    const diagnosticProvider = new DiagnosticProvider();
    const diffProvider = new DiffContentProvider();

    // Register Diff Document Content Provider
    context.subscriptions.push(
        vscode.workspace.registerTextDocumentContentProvider(
            DiffContentProvider.Scheme,
            diffProvider
        )
    );

    // Register Sidebar Webview View Provider
    const sidebarProvider = new SidebarViewProvider(
        context.extensionUri,
        backendClient,
        diagnosticProvider,
        diffProvider
    );

    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            SidebarViewProvider.viewType,
            sidebarProvider
        )
    );

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
    const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document: vscode.TextDocument) => {
        const config = vscode.workspace.getConfiguration('flawfix');
        const autoScan = config.get<boolean>('autoScanOnSave', true);

        if (autoScan && SUPPORTED_LANGUAGES.includes(document.languageId)) {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor && activeEditor.document.uri.toString() === document.uri.toString()) {
                await sidebarProvider.scanActiveDocument();
            }
        }
    });

    context.subscriptions.push(onSaveListener);
}

export function deactivate() {}
