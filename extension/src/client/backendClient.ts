import axios, { AxiosInstance } from 'axios';
import * as vscode from 'vscode';

export interface VulnerabilityFinding {
    vulnerability_id: string;
    title: string;
    cwe_id: string;
    severity: string;
    function_name: string;
    affected_lines: number[];
    root_cause: string;
    security_impact: string;
    recommendation: string;
    patch_candidates: Array<{
        patch_id: string;
        title: string;
        description: string;
        patched_code: string;
        optimization_notes?: string;
        approach_type?: string;
        is_recommended?: boolean;
    }>;
}

export interface SecurityAnalysisResult {
    is_vulnerable: boolean;
    total_vulnerabilities: number;
    vulnerabilities: VulnerabilityFinding[];
    general_optimizations: Array<{
        title: string;
        description: string;
        impact: string;
    }>;
    summary: string;
    analysis_time_ms: number;
}

export interface SyntaxErrorItem {
    line: number;
    column: number;
    message: string;
    severity: string;
    source?: string;
    error_type?: string;
    explanation?: string;
    original_message?: string;
}

export interface FullAnalysisResponse {
    language: string;
    file_name?: string;
    syntax_result: {
        is_valid: boolean;
        errors: SyntaxErrorItem[];
    };
    ir_generated: boolean;
    analysis_result?: SecurityAnalysisResult;
    error?: string;
}


export interface VerifyPatchResponse {
    is_verified: boolean;
    syntax_valid: boolean;
    ir_generated: boolean;
    verified_code: string;
    verification_message: string;
    remaining_issues: string[];
    analysis_time_ms: number;
}

export interface ReportResponse {
    report_id: string;
    file_name: string;
    file_path: string;
    download_url: string;
    file_size_bytes: number;
    generated_at: string;
}

export class BackendClient {
    private client: AxiosInstance;
    private baseUrl: string;

    constructor() {
        const config = vscode.workspace.getConfiguration('flawfix');
        this.baseUrl = config.get<string>('backendUrl', 'http://127.0.0.1:8000');
        this.client = axios.create({
            baseURL: this.baseUrl,
            timeout: 120000 // 120s for LLVM compile + AI reasoning
        });
    }

    public async checkHealth(): Promise<boolean> {
        try {
            const res = await this.client.get('/api/health');
            return res.status === 200;
        } catch {
            return false;
        }
    }

    public async analyzeFile(code: string, language: string, fileName: string): Promise<FullAnalysisResponse> {
        const res = await this.client.post<FullAnalysisResponse>('/api/analyze-vulnerabilities', {
            code,
            language,
            file_name: fileName
        });
        return res.data;
    }

    public async verifyPatch(
        originalCode: string,
        patchCode: string,
        functionName: string,
        language: string,
        vulnId?: string,
        fileName?: string
    ): Promise<VerifyPatchResponse> {
        const res = await this.client.post<VerifyPatchResponse>('/api/verify-patch', {
            original_code: originalCode,
            patch_code: patchCode,
            function_name: functionName,
            language,
            vulnerability_id: vulnId,
            file_name: fileName
        });
        return res.data;
    }

    public async generateReport(
        projectName: string,
        fileName: string,
        language: string,
        analysisResult: SecurityAnalysisResult,
        verifiedPatches?: any[],
        originalCode?: string
    ): Promise<ReportResponse> {
        const res = await this.client.post<ReportResponse>('/api/generate-report', {
            project_name: projectName,
            file_name: fileName,
            language,
            analysis_result: analysisResult,
            verified_patches: verifiedPatches || [],
            original_code: originalCode
        });
        return res.data;
    }

    public getReportDownloadUrl(downloadPath: string): string {
        if (downloadPath.startsWith('http')) {
            return downloadPath;
        }
        return `${this.baseUrl}${downloadPath}`;
    }
}
