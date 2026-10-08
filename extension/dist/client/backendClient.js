"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackendClient = void 0;
const axios_1 = require("axios");
const vscode = require("vscode");
class BackendClient {
    client;
    baseUrl;
    constructor() {
        const config = vscode.workspace.getConfiguration('flawfix');
        this.baseUrl = config.get('backendUrl', 'http://127.0.0.1:8000');
        this.client = axios_1.default.create({
            baseURL: this.baseUrl,
            timeout: 120000 // 120s for LLVM compile + AI reasoning
        });
    }
    async checkHealth() {
        try {
            const res = await this.client.get('/api/health');
            return res.status === 200;
        }
        catch {
            return false;
        }
    }
    async analyzeFile(code, language, fileName) {
        const res = await this.client.post('/api/analyze-vulnerabilities', {
            code,
            language,
            file_name: fileName
        });
        return res.data;
    }
    async verifyPatch(originalCode, patchCode, functionName, language, vulnId, fileName) {
        const res = await this.client.post('/api/verify-patch', {
            original_code: originalCode,
            patch_code: patchCode,
            function_name: functionName,
            language,
            vulnerability_id: vulnId,
            file_name: fileName
        });
        return res.data;
    }
    async generateReport(projectName, fileName, language, analysisResult, verifiedPatches, originalCode) {
        const res = await this.client.post('/api/generate-report', {
            project_name: projectName,
            file_name: fileName,
            language,
            analysis_result: analysisResult,
            verified_patches: verifiedPatches || [],
            original_code: originalCode
        });
        return res.data;
    }
    getReportDownloadUrl(downloadPath) {
        if (downloadPath.startsWith('http')) {
            return downloadPath;
        }
        return `${this.baseUrl}${downloadPath}`;
    }
}
exports.BackendClient = BackendClient;
//# sourceMappingURL=backendClient.js.map