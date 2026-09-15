(function () {
    const vscode = acquireVsCodeApi();

    // DOM Elements
    const scanBtn = document.getElementById('scan-btn');
    const reportBtn = document.getElementById('report-btn');
    const statusContainer = document.getElementById('status-container');
    const scorecardContainer = document.getElementById('scorecard-container');
    const vulnList = document.getElementById('vuln-list');
    const optimizationsContainer = document.getElementById('optimizations-container');

    let currentAnalysis = null;

    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            setLoading(true, "Compiling LLVM IR & Analyzing with AI...");
            vscode.postMessage({ command: 'scanFile' });
        });
    }

    if (reportBtn) {
        reportBtn.addEventListener('click', () => {
            vscode.postMessage({ command: 'generateReport' });
        });
    }

    // Handle messages sent from the extension to the webview
    window.addEventListener('message', event => {
        const message = event.data;
        switch (message.type) {
            case 'analysisStarted':
                setLoading(true, "Compiling LLVM IR & Running AI Verification...");
                break;
            case 'analysisComplete':
                setLoading(false);
                currentAnalysis = message.data;
                renderAnalysis(message.data);
                break;
            case 'analysisError':
                setLoading(false);
                renderError(message.error);
                break;
            case 'patchApplied':
                renderPatchStatus(message.vulnId, message.verified, message.message);
                break;
        }
    });

    function setLoading(isLoading, text = "Analyzing...") {
        if (isLoading) {
            statusContainer.innerHTML = `
                <div class="status-box">
                    <div class="spinner"></div>
                    <div>${text}</div>
                </div>
            `;
            statusContainer.style.display = 'block';
            scorecardContainer.style.display = 'none';
            vulnList.innerHTML = '';
            optimizationsContainer.innerHTML = '';
        } else {
            statusContainer.style.display = 'none';
        }
    }

    function renderError(errorMessage) {
        statusContainer.innerHTML = `
            <div class="status-box" style="color: var(--ff-critical);">
                <div style="font-weight: 700; margin-bottom: 4px;">⚠️ Analysis Error</div>
                <div style="font-size: 11px;">${errorMessage}</div>
            </div>
        `;
        statusContainer.style.display = 'block';
    }

    function renderAnalysis(data) {
        if (!data || !data.analysis_result) {
            statusContainer.innerHTML = `
                <div class="status-box">
                    <div>No security scan data available. Click <b>Scan Active File</b> above to analyze.</div>
                </div>
            `;
            statusContainer.style.display = 'block';
            return;
        }

        const result = data.analysis_result;
        reportBtn.style.display = 'flex';

        // Render Scorecards
        const crit = result.vulnerabilities.filter(v => v.severity.toLowerCase() === 'critical').length;
        const high = result.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length;
        const med = result.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium').length;
        const low = result.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low').length;

        scorecardContainer.innerHTML = `
            <div class="scorecard-grid">
                <div class="scorecard-item">
                    <div class="scorecard-value critical-color">${crit}</div>
                    <div class="scorecard-label">Critical</div>
                </div>
                <div class="scorecard-item">
                    <div class="scorecard-value high-color">${high}</div>
                    <div class="scorecard-label">High</div>
                </div>
                <div class="scorecard-item">
                    <div class="scorecard-value medium-color">${med}</div>
                    <div class="scorecard-label">Med</div>
                </div>
                <div class="scorecard-item">
                    <div class="scorecard-value low-color">${low}</div>
                    <div class="scorecard-label">Low</div>
                </div>
            </div>
            <div style="font-size: 11px; margin-bottom: 12px; color: var(--vscode-descriptionForeground);">
                ${result.summary}
            </div>
        `;
        scorecardContainer.style.display = 'block';

        // Render Vulnerabilities
        if (result.vulnerabilities.length === 0) {
            vulnList.innerHTML = `
                <div class="status-box" style="color: var(--ff-verified);">
                    <div style="font-size: 18px; margin-bottom: 4px;">🛡️</div>
                    <div style="font-weight: 700;">No Vulnerabilities Found!</div>
                    <div style="font-size: 11px;">Source code passed syntax validation and semantic LLVM IR security audit.</div>
                </div>
            `;
        } else {
            vulnList.innerHTML = result.vulnerabilities.map((v, idx) => {
                const sevClass = v.severity.toLowerCase();
                const linesStr = v.affected_lines && v.affected_lines.length > 0 ? `Line ${v.affected_lines.join(', ')}` : '';
                
                const patchHtml = v.patch_candidates && v.patch_candidates.length > 0 ? `
                    <div class="patch-box" id="patch-box-${v.vulnerability_id}">
                        <div class="patch-header">
                            <span>💡 ${v.patch_candidates[0].title}</span>
                            <span class="badge badge-low">AI Patch</span>
                        </div>
                        <div style="font-size: 10px; margin-bottom: 6px;">${v.patch_candidates[0].description}</div>
                        <pre><code>${escapeHtml(v.patch_candidates[0].patched_code)}</code></pre>
                        ${v.patch_candidates[0].optimization_notes ? `<div style="font-size: 10px; color: #10b981; margin-top: 4px;">⚡ ${v.patch_candidates[0].optimization_notes}</div>` : ''}
                        <div class="patch-actions">
                            <button class="btn-secondary preview-patch-btn" data-patch-id="${v.patch_candidates[0].patch_id}" data-vuln-id="${v.vulnerability_id}">
                                👁️ Preview Diff
                            </button>
                            <button class="btn-success apply-patch-btn" data-patch-id="${v.patch_candidates[0].patch_id}" data-func-name="${v.function_name}" data-vuln-id="${v.vulnerability_id}">
                                ⚡ Apply & Verify
                            </button>
                        </div>
                    </div>
                ` : '';

                return `
                    <div class="vuln-card ${sevClass}" id="card-${v.vulnerability_id}">
                        <div class="vuln-header" onclick="toggleCard('${v.vulnerability_id}')">
                            <div class="vuln-title-group">
                                <div class="vuln-title">${v.title}</div>
                                <div class="vuln-cwe">${v.cwe_id} • ${linesStr}</div>
                            </div>
                            <span class="badge badge-${sevClass}">${v.severity}</span>
                        </div>
                        <div class="vuln-body" id="body-${v.vulnerability_id}">
                            <div class="section-label">Root Cause (Explainable AI)</div>
                            <div>${v.root_cause}</div>
                            
                            <div class="section-label">Security Exploit Impact</div>
                            <div>${v.security_impact}</div>
                            
                            <div class="section-label">Remediation Guideline</div>
                            <div>${v.recommendation}</div>

                            ${patchHtml}
                        </div>
                    </div>
                `;
            }).join('');

            // Attach event listeners to preview & apply buttons
            document.querySelectorAll('.preview-patch-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const vulnId = btn.getAttribute('data-vuln-id');
                    const vuln = result.vulnerabilities.find(v => v.vulnerability_id === vulnId);
                    if (vuln && vuln.patch_candidates.length > 0) {
                        vscode.postMessage({
                            command: 'previewPatch',
                            patchCode: vuln.patch_candidates[0].patched_code,
                            functionName: vuln.function_name,
                            vulnId: vulnId
                        });
                    }
                });
            });

            document.querySelectorAll('.apply-patch-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const vulnId = btn.getAttribute('data-vuln-id');
                    const funcName = btn.getAttribute('data-func-name');
                    const vuln = result.vulnerabilities.find(v => v.vulnerability_id === vulnId);
                    if (vuln && vuln.patch_candidates.length > 0) {
                        btn.innerHTML = `⏳ Verifying...`;
                        btn.disabled = true;
                        vscode.postMessage({
                            command: 'applyAndVerifyPatch',
                            patchCode: vuln.patch_candidates[0].patched_code,
                            functionName: funcName,
                            vulnId: vulnId
                        });
                    }
                });
            });
        }

        // Render Optimizations
        if (result.general_optimizations && result.general_optimizations.length > 0) {
            optimizationsContainer.innerHTML = `
                <div style="font-weight: 700; font-size: 11px; margin-top: 14px; margin-bottom: 6px; text-transform: uppercase; color: var(--vscode-descriptionForeground);">
                    ⚡ AI Code Optimizations
                </div>
                ${result.general_optimizations.map(opt => `
                    <div class="scorecard-item" style="text-align: left; padding: 6px 8px; margin-bottom: 6px;">
                        <div style="font-weight: 600; font-size: 11px; color: #38bdf8;">${opt.title}</div>
                        <div style="font-size: 10px; margin-top: 2px;">${opt.description}</div>
                        <div style="font-size: 9px; color: #10b981; margin-top: 2px;"><b>Benefit:</b> ${opt.impact}</div>
                    </div>
                `).join('')}
            `;
        }
    }

    function renderPatchStatus(vulnId, verified, message) {
        const patchBox = document.getElementById(`patch-box-${vulnId}`);
        if (patchBox) {
            if (verified) {
                patchBox.innerHTML = `
                    <div style="background-color: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; padding: 8px; border-radius: 4px;">
                        <div style="color: #10b981; font-weight: 700; display: flex; align-items: center; gap: 4px;">
                            ✓ VERIFIED & APPLIED
                        </div>
                        <div style="font-size: 10px; margin-top: 4px;">${message}</div>
                    </div>
                `;
            } else {
                patchBox.innerHTML += `
                    <div style="color: #ef4444; font-size: 10px; margin-top: 6px;">
                        ⚠️ Verification warning: ${message}
                    </div>
                `;
            }
        }
    }

    window.toggleCard = function (vulnId) {
        const body = document.getElementById(`body-${vulnId}`);
        if (body) {
            body.style.display = body.style.display === 'none' ? 'block' : 'none';
        }
    };

    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
})();
