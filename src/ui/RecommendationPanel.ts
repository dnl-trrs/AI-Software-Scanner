import * as vscode from 'vscode';

export class RecommendationPanel {
    public static currentPanel: RecommendationPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private _recommendations: any[] = [];
    private _currentIndex: number = 0;

    public static createOrShow(extensionUri: vscode.Uri, recommendations: any[] | any) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        // Convert single recommendation to array if needed
        const recsArray = Array.isArray(recommendations) ? recommendations : [recommendations];

        // If we already have a panel, show it
        if (RecommendationPanel.currentPanel) {
            RecommendationPanel.currentPanel._panel.reveal(column);
            RecommendationPanel.currentPanel._recommendations = recsArray;
            RecommendationPanel.currentPanel._currentIndex = 0;
            RecommendationPanel.currentPanel._update();
            return;
        }

        // Otherwise, create a new panel
        const panel = vscode.window.createWebviewPanel(
            'recommendationDetails',
            'Recommendation Details',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [extensionUri]
            }
        );

        RecommendationPanel.currentPanel = new RecommendationPanel(panel, extensionUri, recsArray);
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, recommendations: any[]) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._recommendations = recommendations;
        this._currentIndex = 0;

        // Set the webview's initial html content
        this._update();

        // Listen for when the panel is disposed
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        // Handle messages from the webview
        this._panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'accept':
                        vscode.commands.executeCommand('ai-software-scanner.acceptRecommendation', message.data);
                        // Move to next recommendation or close if last
                        if (this._currentIndex < this._recommendations.length - 1) {
                            this._currentIndex++;
                            this._update();
                        } else {
                            vscode.window.setStatusBarMessage(`✅ All ${this._recommendations.length} recommendations reviewed!`, 3000);
                            this._panel.dispose();
                        }
                        break;
                    case 'decline':
                        vscode.commands.executeCommand('ai-software-scanner.declineRecommendation', message.data);
                        // Move to next recommendation or close if last
                        if (this._currentIndex < this._recommendations.length - 1) {
                            this._currentIndex++;
                            this._update();
                        } else {
                            vscode.window.setStatusBarMessage(`✅ All ${this._recommendations.length} recommendations reviewed!`, 3000);
                            this._panel.dispose();
                        }
                        break;
                    case 'learnMore':
                        vscode.commands.executeCommand('ai-software-scanner.showEducation', message.data);
                        break;
                    case 'previous':
                        if (this._currentIndex > 0) {
                            this._currentIndex--;
                            this._update();
                        }
                        break;
                    case 'next':
                        if (this._currentIndex < this._recommendations.length - 1) {
                            this._currentIndex++;
                            this._update();
                        }
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    public dispose() {
        RecommendationPanel.currentPanel = undefined;

        // Clean up our resources
        this._panel.dispose();

        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    private _update() {
        const currentRec = this._recommendations[this._currentIndex];
        this._panel.webview.html = this._getHtmlForWebview(this._panel.webview, currentRec);
    }

    private _getHtmlForWebview(webview: vscode.Webview, recommendation: any) {
        const nonce = this.getNonce();
        const isFirst = this._currentIndex === 0;
        const isLast = this._currentIndex === this._recommendations.length - 1;
        const currentNum = this._currentIndex + 1;
        const totalNum = this._recommendations.length;

        return `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
                <title>Recommendation Details</title>
                <style>
                    body {
                        font-family: var(--vscode-font-family);
                        color: var(--vscode-foreground);
                        background: var(--vscode-editor-background);
                        padding: 0;
                        margin: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                    }

                    .modal-container {
                        background: var(--vscode-editor-background);
                        border: 1px solid var(--vscode-widget-border);
                        border-radius: 8px;
                        width: 900px;
                        max-width: 95vw;
                        height: 90vh;
                        max-height: 900px;
                        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
                        animation: slideIn 0.3s ease-out;
                        display: flex;
                        flex-direction: column;
                    }

                    @keyframes slideIn {
                        from {
                            opacity: 0;
                            transform: translateY(-20px);
                        }
                        to {
                            opacity: 1;
                            transform: translateY(0);
                        }
                    }

                    .modal-header {
                        padding: 20px 24px;
                        border-bottom: 1px solid var(--vscode-widget-border);
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        flex-shrink: 0;
                        min-height: 70px;
                    }

                    .modal-title {
                        font-size: 18px;
                        font-weight: 600;
                        display: flex;
                        align-items: center;
                        gap: 12px;
                        flex: 1;
                    }
                    
                    .navigation-controls {
                        display: flex;
                        align-items: center;
                        gap: 16px;
                    }
                    
                    .nav-button {
                        width: 36px;
                        height: 36px;
                        border-radius: 50%;
                        border: 1px solid var(--vscode-widget-border);
                        background: transparent;
                        color: var(--vscode-foreground);
                        cursor: pointer;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: all 0.2s;
                        font-size: 18px;
                    }
                    
                    .nav-button:hover:not(:disabled) {
                        background: var(--vscode-button-hoverBackground);
                        color: var(--vscode-button-foreground);
                    }
                    
                    .nav-button:disabled {
                        opacity: 0.4;
                        cursor: not-allowed;
                    }
                    
                    .counter {
                        font-size: 14px;
                        color: var(--vscode-descriptionForeground);
                        font-weight: normal;
                        padding: 6px 14px;
                        background: var(--vscode-badge-background);
                        border-radius: 12px;
                        white-space: nowrap;
                    }
                    
                    .nav-group {
                        display: flex;
                        align-items: center;
                        gap: 12px;
                    }

                    .severity-badge {
                        padding: 4px 10px;
                        border-radius: 12px;
                        font-size: 11px;
                        font-weight: bold;
                        text-transform: uppercase;
                        display: inline-block;
                    }

                    .severity-critical {
                        background: #ff0000;
                        color: white;
                    }

                    .severity-high {
                        background: #ff8800;
                        color: white;
                    }

                    .severity-medium {
                        background: #ffcc00;
                        color: black;
                    }

                    .severity-low {
                        background: #0099ff;
                        color: white;
                    }

                    .modal-body {
                        padding: 24px;
                        flex: 1;
                        overflow-y: auto;
                        display: flex;
                        flex-direction: column;
                        gap: 20px;
                    }

                    .section {
                        display: flex;
                        flex-direction: column;
                        min-height: 0;
                    }
                    
                    .section.issue-section {
                        flex-shrink: 0;
                    }
                    
                    .section.code-section {
                        flex: 0 1 auto;
                        min-height: 120px;
                        max-height: 250px;
                    }
                    
                    .section.recommendation-section {
                        flex: 0 1 auto;
                        min-height: 150px;
                        max-height: 300px;
                    }
                    
                    .section.explanation-section {
                        flex: 1 1 auto;
                        min-height: 150px;
                        overflow-y: auto;
                    }


                    .section-title {
                        font-size: 14px;
                        font-weight: 600;
                        margin-bottom: 8px;
                        color: var(--vscode-foreground);
                        display: flex;
                        align-items: center;
                        gap: 12px;
                    }

                    .section-content {
                        font-size: 13px;
                        line-height: 1.6;
                        color: var(--vscode-descriptionForeground);
                        flex: 1;
                        overflow-y: auto;
                        padding-right: 8px;
                    }
                    
                    .section-content::-webkit-scrollbar {
                        width: 6px;
                    }
                    
                    .section-content::-webkit-scrollbar-thumb {
                        background-color: var(--vscode-scrollbarSlider-background);
                        border-radius: 3px;
                    }
                    
                    .section-content::-webkit-scrollbar-thumb:hover {
                        background-color: var(--vscode-scrollbarSlider-hoverBackground);
                    }

                    .code-block {
                        background: var(--vscode-textCodeBlock-background);
                        border: 1px solid var(--vscode-widget-border);
                        border-radius: 4px;
                        padding: 12px;
                        margin: 8px 0;
                        font-family: var(--vscode-editor-font-family);
                        font-size: 12px;
                        line-height: 1.5;
                        overflow: auto;
                        white-space: pre-wrap;
                        word-break: break-word;
                        flex: 1;
                        min-height: 60px;
                        max-height: 150px;
                    }
                    
                    .code-block::-webkit-scrollbar {
                        width: 6px;
                        height: 6px;
                    }
                    
                    .code-block::-webkit-scrollbar-thumb {
                        background-color: var(--vscode-scrollbarSlider-background);
                        border-radius: 3px;
                    }
                    
                    .code-block::-webkit-scrollbar-thumb:hover {
                        background-color: var(--vscode-scrollbarSlider-hoverBackground);
                    }

                    .code-before {
                        background: rgba(255, 0, 0, 0.1);
                        border-left: 3px solid #ff0000;
                    }

                    .code-after {
                        background: rgba(0, 255, 0, 0.1);
                        border-left: 3px solid #00ff00;
                    }

                    .modal-footer {
                        padding: 20px 24px;
                        border-top: 1px solid var(--vscode-widget-border);
                        display: flex;
                        justify-content: flex-end;
                        align-items: center;
                        gap: 12px;
                        flex-shrink: 0;
                        min-height: 70px;
                    }

                    .button {
                        padding: 8px 20px;
                        border: none;
                        border-radius: 2px;
                        font-size: 13px;
                        font-family: var(--vscode-font-family);
                        cursor: pointer;
                        transition: background-color 0.2s;
                    }

                    .button-primary {
                        background: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                    }

                    .button-primary:hover {
                        background: var(--vscode-button-hoverBackground);
                    }

                    .button-secondary {
                        background: transparent;
                        color: var(--vscode-foreground);
                        border: 1px solid var(--vscode-widget-border);
                    }

                    .button-secondary:hover {
                        background: var(--vscode-widget-shadow);
                    }

                    .location-info {
                        display: inline-flex;
                        align-items: center;
                        gap: 6px;
                        padding: 3px 8px;
                        background: var(--vscode-badge-background);
                        color: var(--vscode-badge-foreground);
                        border-radius: 4px;
                        font-size: 12px;
                        font-weight: normal;
                    }

                    .icon {
                        display: inline-block;
                        width: 16px;
                        height: 16px;
                        margin-right: 4px;
                    }

                    .recommendation-icon {
                        font-size: 20px;
                    }

                    .learn-more-link {
                        color: var(--vscode-textLink-foreground);
                        text-decoration: none;
                        cursor: pointer;
                        font-size: 12px;
                    }

                    .learn-more-link:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="modal-container">
                    <div class="modal-header">
                        <div class="modal-title">
                            <span class="recommendation-icon">💡</span>
                            Recommendation Action
                        </div>
                        <div class="navigation-controls">
                            <span class="severity-badge severity-${recommendation.vulnerability?.severity || 'medium'}">${recommendation.vulnerability?.severity || 'medium'}</span>
                            <div class="nav-group">
                                <button class="nav-button" id="prevBtn" ${isFirst ? 'disabled' : ''} title="Previous recommendation">
                                    ‹
                                </button>
                                <span class="counter">${currentNum} of ${totalNum}</span>
                                <button class="nav-button" id="nextBtn" ${isLast ? 'disabled' : ''} title="Next recommendation">
                                    ›
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="modal-body">
                        <div class="section issue-section">
                            <div class="section-title">
                                Issue Detected
                                <span class="location-info">
                                    📍 Line ${recommendation.vulnerability?.line || recommendation.line || '1'}
                                </span>
                            </div>
                            <div class="section-content">
                                <strong>${recommendation.vulnerability?.type || 'Security Issue'}:</strong><br>
                                ${recommendation.vulnerability?.message || 'Potential security vulnerability detected'}
                            </div>
                        </div>

                        <div class="section code-section">
                            <div class="section-title">Vulnerable Code</div>
                            <div class="code-block code-before">
                                <code>${this.escapeHtml(recommendation.vulnerability?.code || '')}</code>
                            </div>
                        </div>

                        <div class="section recommendation-section">
                            <div class="section-title">Recommended Fix</div>
                            <div class="section-content" style="margin-bottom: 8px;">
                                ${recommendation.vulnerability?.recommendation || 'Apply security best practices'}
                            </div>
                            <div class="code-block code-after">
                                <code>${this.escapeHtml(recommendation.automaticFix || recommendation.vulnerability?.automaticFix || '')}</code>
                            </div>
                        </div>

                        <div class="section explanation-section">
                            <div class="section-title">Why This Matters</div>
                            <div class="section-content">
                                ${recommendation.explanation || recommendation.vulnerability?.educationalContent || 'This recommendation helps improve code security.'}
                                <br><br>
                                <strong>Estimated fix time:</strong> ${recommendation.estimatedFixTime || '5'} minutes<br>
                                <strong>Confidence:</strong> ${recommendation.confidence || '85'}%<br><br>
                                <a class="learn-more-link" id="learnMore">📚 Learn more about ${recommendation.vulnerability?.type || 'this issue'}</a>
                            </div>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button class="button button-secondary" id="declineBtn">Decline</button>
                        <button class="button button-primary" id="acceptBtn">✓ Accept</button>
                    </div>
                </div>

                <script nonce="${nonce}">
                    const vscode = acquireVsCodeApi();
                    const recommendation = ${JSON.stringify(recommendation)};

                    document.getElementById('acceptBtn').addEventListener('click', () => {
                        vscode.postMessage({
                            command: 'accept',
                            data: {
                                vulnerability: recommendation.vulnerability,
                                fix: recommendation.automaticFix || recommendation.vulnerability?.automaticFix
                            }
                        });
                    });

                    document.getElementById('declineBtn').addEventListener('click', () => {
                        vscode.postMessage({
                            command: 'decline',
                            data: recommendation
                        });
                    });

                    document.getElementById('learnMore').addEventListener('click', (e) => {
                        e.preventDefault();
                        vscode.postMessage({
                            command: 'learnMore',
                            data: recommendation.type
                        });
                    });
                    
                    const prevBtn = document.getElementById('prevBtn');
                    const nextBtn = document.getElementById('nextBtn');
                    
                    if (prevBtn) {
                        prevBtn.addEventListener('click', () => {
                            if (!prevBtn.disabled) {
                                vscode.postMessage({ command: 'previous' });
                            }
                        });
                    }
                    
                    if (nextBtn) {
                        nextBtn.addEventListener('click', () => {
                            if (!nextBtn.disabled) {
                                vscode.postMessage({ command: 'next' });
                            }
                        });
                    }
                    
                    // Add keyboard navigation
                    document.addEventListener('keydown', (e) => {
                        if (e.key === 'ArrowLeft' && prevBtn && !prevBtn.disabled) {
                            vscode.postMessage({ command: 'previous' });
                        } else if (e.key === 'ArrowRight' && nextBtn && !nextBtn.disabled) {
                            vscode.postMessage({ command: 'next' });
                        }
                    });
                </script>
            </body>
            </html>`;
    }

    private escapeHtml(unsafe: string): string {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;")
            .replace(/\n/g, "<br>");
    }

    private getNonce() {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }
}