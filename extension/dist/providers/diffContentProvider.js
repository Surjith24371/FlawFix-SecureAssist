"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DiffContentProvider = void 0;
const vscode = require("vscode");
class DiffContentProvider {
    static scheme = 'flawfix-patch';
    contentMap = new Map();
    onDidChangeEmitter = new vscode.EventEmitter();
    onDidChange = this.onDidChangeEmitter.event;
    static get Scheme() {
        return DiffContentProvider.scheme;
    }
    provideTextDocumentContent(uri) {
        return this.contentMap.get(uri.toString()) || '// No patch content available';
    }
    setPatchContent(uri, content) {
        this.contentMap.set(uri.toString(), content);
        this.onDidChangeEmitter.fire(uri);
    }
    async showDiff(originalUri, patchedCode, title) {
        const patchUri = vscode.Uri.parse(`${DiffContentProvider.scheme}://preview/${originalUri.fsPath.replace(/\\/g, '/')}_patched`);
        this.setPatchContent(patchUri, patchedCode);
        await vscode.commands.executeCommand('vscode.diff', originalUri, patchUri, `FlawFix Secure Patch: ${title}`, { preview: true });
    }
}
exports.DiffContentProvider = DiffContentProvider;
//# sourceMappingURL=diffContentProvider.js.map