import * as vscode from 'vscode';

export class DiffContentProvider implements vscode.TextDocumentContentProvider {
    private static scheme = 'flawfix-patch';
    private contentMap = new Map<string, string>();
    private onDidChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
    public onDidChange = this.onDidChangeEmitter.event;

    public static get Scheme(): string {
        return DiffContentProvider.scheme;
    }

    public provideTextDocumentContent(uri: vscode.Uri): string {
        return this.contentMap.get(uri.toString()) || '// No patch content available';
    }

    public setPatchContent(uri: vscode.Uri, content: string) {
        this.contentMap.set(uri.toString(), content);
        this.onDidChangeEmitter.fire(uri);
    }

    public async showDiff(originalUri: vscode.Uri, patchedCode: string, title: string) {
        const patchUri = vscode.Uri.parse(`${DiffContentProvider.scheme}://preview/${originalUri.fsPath.replace(/\\/g, '/')}_patched`);
        this.setPatchContent(patchUri, patchedCode);

        await vscode.commands.executeCommand(
            'vscode.diff',
            originalUri,
            patchUri,
            `FlawFix Secure Patch: ${title}`,
            { preview: true }
        );
    }
}
