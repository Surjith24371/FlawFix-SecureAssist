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
    // Map of vulnerability_id -> selected patch index (0, 1, 2)
    const selectedPatchIndexMap = {};

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
                setLoading(true, "Validating syntax & compiling LLVM IR...");
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
                <div style="font-size: 11px; line-height: 1.4;">${escapeHtml(errorMessage)}</div>
            </div>
        `;
        statusContainer.style.display = 'block';
        scorecardContainer.style.display = 'none';
        vulnList.innerHTML = '';
        optimizationsContainer.innerHTML = '';
    }

    function renderSyntaxErrors(syntaxResult) {
        scorecardContainer.style.display = 'none';
        optimizationsContainer.innerHTML = '';
        reportBtn.style.display = 'none';

        const errors = syntaxResult.errors || [];
        const errorCardsHtml = errors.map(err => {
            const errType = err.error_type || 'SyntaxError';
            const explanation = err.explanation ? `<div class="syntax-explanation">${escapeHtml(err.explanation)}</div>` : '';
            return `
                <div class="syntax-card">
                    <div class="syntax-header">
                        <span class="syntax-badge">${escapeHtml(errType)}</span>
                        <span class="syntax-loc">Line ${err.line}, Col ${err.column}</span>
                        <button class="goto-line-btn" data-line="${err.line}" data-col="${err.column}" title="Jump to error line in editor">
                            📍 Go to Line
                        </button>
                    </div>
                    <div class="syntax-msg">${escapeHtml(err.message)}</div>
                    ${explanation}
                </div>
            `;
        }).join('');

        statusContainer.innerHTML = `
            <div class="syntax-container">
                <div class="syntax-main-header">
                    <span>⛔ Syntax & Compilation Errors Detected</span>
                </div>
                <div class="syntax-sub-header">
                    Source code contains blocking syntax errors. Security analysis and LLVM IR generation were halted to avoid compiler failures. Please fix the following errors:
                </div>
                <div class="syntax-list">
                    ${errorCardsHtml}
                </div>
            </div>
        `;
        statusContainer.style.display = 'block';

        // Attach Go-to-line event listeners
        statusContainer.querySelectorAll('.goto-line-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const line = parseInt(btn.getAttribute('data-line'), 10) || 1;
                const col = parseInt(btn.getAttribute('data-col'), 10) || 1;
                vscode.postMessage({ command: 'goToLine', line, column: col });
            });
        });
    }

    function renderAnalysis(data) {
        if (!data) return;

        // 1. Check if Syntax Validation failed
        if (data.syntax_result && !data.syntax_result.is_valid) {
            renderSyntaxErrors(data.syntax_result);
            return;
        }

        // 2. Check for LLVM timeout or IR generation error
        if (data.error && (!data.analysis_result || !data.analysis_result.vulnerabilities)) {
            renderError(data.error);
            return;
        }

        if (!data.analysis_result) {
            statusContainer.innerHTML = `
                <div class="status-box">
                    <div>No security scan data available. Click <b>Scan Active File</b> above to analyze.</div>
                </div>
            `;
            statusContainer.style.display = 'block';
            return;
        }

        statusContainer.style.display = 'none';
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
            <div style="font-size: 11px; margin-bottom: 12px; color: var(--vscode-descriptionForeground); line-height: 1.4;">
                ${escapeHtml(result.summary)}
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
            vulnList.innerHTML = result.vulnerabilities.map(v => {
                const sevClass = v.severity.toLowerCase();
                const linesStr = v.affected_lines && v.affected_lines.length > 0 ? `Line ${v.affected_lines.join(', ')}` : '';
                
                // Initialize selected patch index to recommended patch if available
                if (selectedPatchIndexMap[v.vulnerability_id] === undefined) {
                    let recIdx = 0;
                    if (v.patch_candidates && v.patch_candidates.length > 0) {
                        const found = v.patch_candidates.findIndex(p => p.is_recommended || (p.title && p.title.toLowerCase().includes('(recommended)')));
                        if (found !== -1) {
                            recIdx = found;
                        }
                    }
                    selectedPatchIndexMap[v.vulnerability_id] = recIdx;
                }
                const activeIdx = selectedPatchIndexMap[v.vulnerability_id];
                const activePatch = (v.patch_candidates && v.patch_candidates[activeIdx]) || (v.patch_candidates && v.patch_candidates[0]);

                let patchSectionHtml = '';
                if (v.patch_candidates && v.patch_candidates.length > 0) {
                    // Generate tabs for multiple patch alternatives
                    const tabsHtml = v.patch_candidates.map((p, pIdx) => {
                        const isRec = Boolean(p.is_recommended || (p.title && p.title.toLowerCase().includes('(recommended)')));
                        const label = p.title.replace(/^Option\s*\d+:\s*/i, '').replace(/\s*\(recommended\)/i, '').trim();
                        const shortName = label.length > 16 ? label.substring(0, 14) + '…' : label;
                        const shortLabel = `Option ${pIdx + 1}: ${shortName}${isRec ? ' (Recommended)' : ''}`;
                        const isActive = pIdx === activeIdx ? 'active' : '';
                        const recClass = isRec ? 'patch-tab-recommended' : '';
                        return `<button class="patch-tab-btn ${isActive} ${recClass}" data-vuln-id="${v.vulnerability_id}" data-patch-index="${pIdx}" title="${escapeHtml(p.title)}">${escapeHtml(shortLabel)}</button>`;
                    }).join('');

                    patchSectionHtml = `
                        <div class="patch-box" id="patch-box-${v.vulnerability_id}">
                            <div class="patch-section-title">
                                <span>🛠️ Secure Patch Alternatives (${v.patch_candidates.length} options)</span>
                            </div>
                            <div class="patch-tabs-container">
                                ${tabsHtml}
                            </div>
                            <div class="patch-detail-view" id="patch-detail-${v.vulnerability_id}">
                                ${renderPatchCandidateContent(v.vulnerability_id, activePatch, v.function_name)}
                            </div>
                        </div>
                    `;
                }

                return `
                    <div class="vuln-card ${sevClass}" id="card-${v.vulnerability_id}">
                        <div class="vuln-header" onclick="toggleCard('${v.vulnerability_id}')">
                            <div class="vuln-title-group">
                                <div class="vuln-title">${escapeHtml(v.title)}</div>
                                <div class="vuln-cwe">${escapeHtml(v.cwe_id)} • ${linesStr}</div>
                            </div>
                            <span class="badge badge-${sevClass}">${escapeHtml(v.severity)}</span>
                        </div>
                        <div class="vuln-body" id="body-${v.vulnerability_id}">
                            <div class="section-label">Root Cause (Explainable AI)</div>
                            <div style="font-size: 11px; line-height: 1.4;">${escapeHtml(v.root_cause)}</div>
                            
                            <div class="section-label">Security Exploit Impact</div>
                            <div style="font-size: 11px; line-height: 1.4;">${escapeHtml(v.security_impact)}</div>
                            
                            <div class="section-label">Remediation Guideline</div>
                            <div style="font-size: 11px; line-height: 1.4;">${escapeHtml(v.recommendation)}</div>

                            ${patchSectionHtml}
                        </div>
                    </div>
                `;
            }).join('');

            // Attach tab switching events
            document.querySelectorAll('.patch-tab-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const vulnId = btn.getAttribute('data-vuln-id');
                    const patchIdx = parseInt(btn.getAttribute('data-patch-index'), 10);
                    selectedPatchIndexMap[vulnId] = patchIdx;

                    // Update active tab buttons
                    const container = btn.closest('.patch-tabs-container');
                    if (container) {
                        container.querySelectorAll('.patch-tab-btn').forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                    }

                    // Update patch detail view
                    const vuln = result.vulnerabilities.find(item => item.vulnerability_id === vulnId);
                    if (vuln && vuln.patch_candidates[patchIdx]) {
                        const detailView = document.getElementById(`patch-detail-${vulnId}`);
                        if (detailView) {
                            detailView.innerHTML = renderPatchCandidateContent(vulnId, vuln.patch_candidates[patchIdx], vuln.function_name);
                            attachPatchActionListeners(vulnId, vuln.function_name);
                        }
                    }
                });
            });

            // Attach preview and apply button handlers for all vulnerabilities
            result.vulnerabilities.forEach(v => {
                attachPatchActionListeners(v.vulnerability_id, v.function_name);
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
                        <div style="font-weight: 600; font-size: 11px; color: #38bdf8;">${escapeHtml(opt.title)}</div>
                        <div style="font-size: 10px; margin-top: 2px;">${escapeHtml(opt.description)}</div>
                        <div style="font-size: 9px; color: #10b981; margin-top: 2px;"><b>Benefit:</b> ${escapeHtml(opt.impact)}</div>
                    </div>
                `).join('')}
            `;
        }
    }

    function renderPatchCandidateContent(vulnId, patch, functionName) {
        if (!patch) return '';
        const isRec = Boolean(patch.is_recommended || (patch.title && patch.title.toLowerCase().includes('(recommended)')));
        const approachBadge = patch.approach_type ? `<span class="badge badge-low">${escapeHtml(patch.approach_type)}</span>` : '<span class="badge badge-low">AI Patch</span>';
        const recBadge = isRec ? `<span class="badge badge-recommended">★ (Recommended)</span>` : '';
        return `
            <div class="patch-header">
                <span class="patch-title-text">💡 ${escapeHtml(patch.title)}</span>
                <div class="patch-header-badges">
                    ${recBadge}
                    ${approachBadge}
                </div>
            </div>
            <div style="font-size: 10px; margin-bottom: 6px; color: var(--vscode-descriptionForeground); line-height: 1.3;">
                ${escapeHtml(patch.description)}
            </div>
            <pre><code>${escapeHtml(patch.patched_code)}</code></pre>
            ${patch.optimization_notes ? `<div style="font-size: 10px; color: #10b981; margin-top: 4px;">⚡ ${escapeHtml(patch.optimization_notes)}</div>` : ''}
            <div class="patch-actions">
                <button class="btn-secondary preview-patch-btn" data-patch-id="${patch.patch_id}" data-vuln-id="${vulnId}">
                    👁️ Preview Diff
                </button>
                <button class="btn-success apply-patch-btn" data-patch-id="${patch.patch_id}" data-func-name="${functionName}" data-vuln-id="${vulnId}">
                    ⚡ Apply & Verify
                </button>
            </div>
        `;
    }

    function attachPatchActionListeners(vulnId, functionName) {
        const detailView = document.getElementById(`patch-detail-${vulnId}`);
        if (!detailView) return;

        const previewBtn = detailView.querySelector('.preview-patch-btn');
        if (previewBtn) {
            previewBtn.onclick = (e) => {
                e.stopPropagation();
                if (!currentAnalysis || !currentAnalysis.analysis_result) return;
                const vuln = currentAnalysis.analysis_result.vulnerabilities.find(v => v.vulnerability_id === vulnId);
                const activeIdx = selectedPatchIndexMap[vulnId] || 0;
                if (vuln && vuln.patch_candidates[activeIdx]) {
                    vscode.postMessage({
                        command: 'previewPatch',
                        patchCode: vuln.patch_candidates[activeIdx].patched_code,
                        functionName: functionName || vuln.function_name,
                        vulnId: vulnId
                    });
                }
            };
        }

        const applyBtn = detailView.querySelector('.apply-patch-btn');
        if (applyBtn) {
            applyBtn.onclick = (e) => {
                e.stopPropagation();
                if (!currentAnalysis || !currentAnalysis.analysis_result) return;
                const vuln = currentAnalysis.analysis_result.vulnerabilities.find(v => v.vulnerability_id === vulnId);
                const activeIdx = selectedPatchIndexMap[vulnId] || 0;
                if (vuln && vuln.patch_candidates[activeIdx]) {
                    applyBtn.innerHTML = `⏳ Verifying...`;
                    applyBtn.disabled = true;
                    vscode.postMessage({
                        command: 'applyAndVerifyPatch',
                        patchCode: vuln.patch_candidates[activeIdx].patched_code,
                        functionName: functionName || vuln.function_name,
                        vulnId: vulnId
                    });
                }
            };
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
                        <div style="font-size: 10px; margin-top: 4px; line-height: 1.3;">${escapeHtml(message)}</div>
                    </div>
                `;
            } else {
                const existingWarn = patchBox.querySelector('.patch-warn-box');
                if (existingWarn) existingWarn.remove();
                
                const warnDiv = document.createElement('div');
                warnDiv.className = 'patch-warn-box';
                warnDiv.style.cssText = 'color: #ef4444; font-size: 10px; margin-top: 6px; padding: 6px; background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 4px;';
                warnDiv.innerHTML = `⚠️ Verification failed: ${escapeHtml(message)}`;
                patchBox.appendChild(warnDiv);

                // Reset button state
                const applyBtn = patchBox.querySelector('.apply-patch-btn');
                if (applyBtn) {
                    applyBtn.innerHTML = `⚡ Apply & Verify`;
                    applyBtn.disabled = false;
                }
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
        if (unsafe === undefined || unsafe === null) return '';
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
})();
