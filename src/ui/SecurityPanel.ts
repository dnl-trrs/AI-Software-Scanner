/**
 * Security Panel Webview Provider
 * Displays vulnerabilities, recommendations, and educational content
 * This comprehensive view is our competitive advantage
 */

import * as vscode from 'vscode';
import { Vulnerability } from '../scanner/SecurityScanner';
import { AIRecommendation } from '../ai/AIRecommendationEngine';

export class SecurityPanelProvider {
    public static currentPanel: SecurityPanelProvider | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];
    private _vulnerabilities: Vulnerability[] = [];
    private _recommendations: AIRecommendation[] = [];

    public static createOrShow(extensionUri: vscode.Uri) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (SecurityPanelProvider.currentPanel) {
            SecurityPanelProvider.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'securityPanel',
            '🛡️ AI Security Scanner',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [extensionUri]
            }
        );

        SecurityPanelProvider.currentPanel = new SecurityPanelProvider(panel, extensionUri);
    }

    public static update(vulnerabilities: Vulnerability[], recommendations: AIRecommendation[]) {
        if (SecurityPanelProvider.currentPanel) {
            SecurityPanelProvider.currentPanel._vulnerabilities = vulnerabilities;
            SecurityPanelProvider.currentPanel._recommendations = recommendations;
            SecurityPanelProvider.currentPanel._update();
        }
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._update();

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'applyFix':
                        vscode.commands.executeCommand(
                            'ai-software-scanner.applyFix',
                            message.vulnerability,
                            message.fix
                        );
                        break;
                    case 'learnMore':
                        vscode.commands.executeCommand(
                            'ai-software-scanner.showEducation',
                            message.content
                        );
                        break;
                    case 'openFile':
                        vscode.window.showTextDocument(vscode.Uri.file(message.file));
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    public dispose() {
        SecurityPanelProvider.currentPanel = undefined;
        this._panel.dispose();

        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    private _update() {
        const webview = this._panel.webview;
        this._panel.webview.html = this._getHtmlForWebview(webview);
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const stats = this._calculateStats();
        
        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Security Scanner</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    color: var(--vscode-foreground);
                    background-color: var(--vscode-editor-background);
                    padding: 20px;
                    line-height: 1.6;
                }
                
                .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid var(--vscode-panel-border);
                }
                
                h1 {
                    color: var(--vscode-foreground);
                    font-size: 24px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                
                .differentiator {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                
                .stats-container {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 15px;
                    margin-bottom: 30px;
                }
                
                .stat-card {
                    background: var(--vscode-editor-inactiveSelectionBackground);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid var(--vscode-panel-border);
                }
                
                .stat-value {
                    font-size: 28px;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                
                .stat-label {
                    font-size: 12px;
                    opacity: 0.8;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                .critical { color: #e74c3c; }
                .high { color: #e67e22; }
                .medium { color: #f39c12; }
                .low { color: #3498db; }
                .success { color: #27ae60; }
                
                .vulnerability-list {
                    margin-top: 30px;
                }
                
                .vulnerability-item {
                    background: var(--vscode-editor-inactiveSelectionBackground);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                    transition: all 0.3s ease;
                }
                
                .vulnerability-item:hover {
                    transform: translateX(5px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                
                .vuln-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: start;
                    margin-bottom: 15px;
                }
                
                .vuln-title {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                
                .severity-badge {
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 11px;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                .severity-critical {
                    background: rgba(231, 76, 60, 0.2);
                    color: #e74c3c;
                }
                
                .severity-high {
                    background: rgba(230, 126, 34, 0.2);
                    color: #e67e22;
                }
                
                .severity-medium {
                    background: rgba(243, 156, 18, 0.2);
                    color: #f39c12;
                }
                
                .severity-low {
                    background: rgba(52, 152, 219, 0.2);
                    color: #3498db;
                }
                
                .vuln-type {
                    font-weight: 600;
                    font-size: 16px;
                }
                
                .vuln-location {
                    font-size: 12px;
                    opacity: 0.8;
                    margin-top: 5px;
                    cursor: pointer;
                    text-decoration: underline;
                }
                
                .vuln-message {
                    margin: 15px 0;
                    padding: 12px;
                    background: var(--vscode-editor-background);
                    border-left: 3px solid var(--vscode-inputValidation-warningBorder);
                    border-radius: 4px;
                }
                
                .recommendation-section {
                    margin-top: 20px;
                    padding: 15px;
                    background: var(--vscode-editor-background);
                    border-radius: 8px;
                    border: 1px solid var(--vscode-panel-border);
                }
                
                .recommendation-header {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    margin-bottom: 12px;
                    font-weight: 600;
                    color: #27ae60;
                }
                
                .fix-code {
                    background: var(--vscode-editor-inactiveSelectionBackground);
                    padding: 12px;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                    font-size: 13px;
                    margin: 10px 0;
                    white-space: pre-wrap;
                    overflow-x: auto;
                }
                
                .action-buttons {
                    display: flex;
                    gap: 10px;
                    margin-top: 15px;
                }
                
                .button {
                    padding: 8px 16px;
                    border-radius: 4px;
                    border: none;
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                
                .button-primary {
                    background: #3498db;
                    color: white;
                }
                
                .button-primary:hover {
                    background: #2980b9;
                    transform: translateY(-1px);
                }
                
                .button-secondary {
                    background: var(--vscode-button-secondaryBackground);
                    color: var(--vscode-button-secondaryForeground);
                }
                
                .button-secondary:hover {
                    background: var(--vscode-button-secondaryHoverBackground);
                }
                
                .best-practices {
                    margin-top: 15px;
                    padding: 12px;
                    background: var(--vscode-editor-background);
                    border-radius: 4px;
                }
                
                .best-practices h4 {
                    margin-bottom: 8px;
                    color: #3498db;
                }
                
                .best-practices ul {
                    margin-left: 20px;
                }
                
                .best-practices li {
                    margin: 4px 0;
                    font-size: 13px;
                }
                
                .learning-resources {
                    margin-top: 15px;
                }
                
                .resource-link {
                    display: inline-block;
                    margin: 4px 8px 4px 0;
                    padding: 4px 10px;
                    background: var(--vscode-editor-inactiveSelectionBackground);
                    border-radius: 4px;
                    font-size: 12px;
                    text-decoration: none;
                    color: var(--vscode-textLink-foreground);
                    transition: all 0.3s ease;
                }
                
                .resource-link:hover {
                    background: var(--vscode-editor-selectionBackground);
                    transform: translateY(-1px);
                }
                
                .confidence-meter {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin: 10px 0;
                }
                
                .confidence-bar {
                    flex: 1;
                    height: 8px;
                    background: var(--vscode-editor-inactiveSelectionBackground);
                    border-radius: 4px;
                    overflow: hidden;
                }
                
                .confidence-fill {
                    height: 100%;
                    background: linear-gradient(90deg, #3498db, #27ae60);
                    transition: width 0.5s ease;
                }
                
                .empty-state {
                    text-align: center;
                    padding: 60px 20px;
                }
                
                .empty-icon {
                    font-size: 64px;
                    margin-bottom: 20px;
                    opacity: 0.5;
                }
                
                .empty-title {
                    font-size: 20px;
                    margin-bottom: 10px;
                }
                
                .empty-description {
                    opacity: 0.8;
                    margin-bottom: 20px;
                }
                
                .feature-highlight {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    text-align: center;
                }
                
                .feature-highlight h3 {
                    margin-bottom: 10px;
                }
                
                .feature-list {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 10px;
                    margin-top: 15px;
                    text-align: left;
                }
                
                .feature-item {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ AI Security Scanner Results</h1>
                <div class="differentiator">Beyond Detection</div>
            </div>
            
            ${this._vulnerabilities.length === 0 ? this._getEmptyState() : this._getResultsContent(stats)}
            
            <script>
                const vscode = acquireVsCodeApi();
                
                function applyFix(vulnId, fix) {
                    const vuln = ${JSON.stringify(this._vulnerabilities)}.find(v => v.id === vulnId);
                    vscode.postMessage({
                        command: 'applyFix',
                        vulnerability: vuln,
                        fix: fix
                    });
                }
                
                function learnMore(content) {
                    vscode.postMessage({
                        command: 'learnMore',
                        content: content
                    });
                }
                
                function openFile(file) {
                    vscode.postMessage({
                        command: 'openFile',
                        file: file
                    });
                }
            </script>
        </body>
        </html>`;
    }

    private _getEmptyState(): string {
        return `
            <div class="empty-state">
                <div class="empty-icon">🔍</div>
                <h2 class="empty-title">No Security Issues Detected</h2>
                <p class="empty-description">
                    Your code appears to be secure! The AI Scanner continuously monitors for:
                </p>
                <div class="feature-highlight">
                    <h3>What Sets Us Apart</h3>
                    <div class="feature-list">
                        <div class="feature-item">✅ Automated fix suggestions</div>
                        <div class="feature-item">📚 Educational content</div>
                        <div class="feature-item">🎯 Actionable recommendations</div>
                        <div class="feature-item">⚡ Quick fix integration</div>
                    </div>
                    <p style="margin-top: 15px; font-size: 14px;">
                        Unlike Snyk AI, Zerothreat, and Qwiet AI, we don't just find problems – 
                        we provide solutions and teach secure coding practices.
                    </p>
                </div>
                <button class="button button-primary" onclick="vscode.postMessage({command: 'scanAgain'})">
                    Scan Again
                </button>
            </div>
        `;
    }

    private _getResultsContent(stats: any): string {
        return `
            <div class="stats-container">
                <div class="stat-card">
                    <div class="stat-value critical">${stats.critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value high">${stats.high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value medium">${stats.medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value low">${stats.low}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value success">${stats.fixTime}m</div>
                    <div class="stat-label">Est. Fix Time</div>
                </div>
            </div>
            
            <div class="vulnerability-list">
                <h2>Security Vulnerabilities</h2>
                ${this._vulnerabilities.map((vuln, index) => this._getVulnerabilityCard(vuln, this._recommendations[index])).join('')}
            </div>
        `;
    }

    private _getVulnerabilityCard(vuln: Vulnerability, recommendation?: AIRecommendation): string {
        return `
            <div class="vulnerability-item">
                <div class="vuln-header">
                    <div class="vuln-title">
                        <span class="vuln-type">${vuln.type.replace(/_/g, ' ')}</span>
                        <span class="severity-badge severity-${vuln.severity}">${vuln.severity}</span>
                    </div>
                    <div class="vuln-location" onclick="openFile('${vuln.file}')">
                        📄 ${vuln.file.split('/').pop()} : Line ${vuln.line}
                    </div>
                </div>
                
                <div class="vuln-message">
                    ⚠️ ${vuln.message}
                </div>
                
                ${recommendation ? this._getRecommendationSection(vuln, recommendation) : ''}
            </div>
        `;
    }

    private _getRecommendationSection(vuln: Vulnerability, rec: AIRecommendation): string {
        return `
            <div class="recommendation-section">
                <div class="recommendation-header">
                    💡 AI-Powered Recommendation
                </div>
                
                <div class="confidence-meter">
                    <span>Confidence:</span>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${rec.confidence}%"></div>
                    </div>
                    <span>${rec.confidence}%</span>
                </div>
                
                <p>${rec.explanation}</p>
                
                ${rec.automaticFix ? `
                    <div class="fix-code">${this._escapeHtml(rec.automaticFix)}</div>
                ` : ''}
                
                <div class="best-practices">
                    <h4>Best Practices:</h4>
                    <ul>
                        ${rec.bestPractices.slice(0, 3).map(bp => `<li>${bp}</li>`).join('')}
                    </ul>
                </div>
                
                ${rec.learningResources.length > 0 ? `
                    <div class="learning-resources">
                        <strong>📚 Learning Resources:</strong><br>
                        ${rec.learningResources.map(r => `
                            <a href="#" class="resource-link" onclick="learnMore('${this._escapeHtml(JSON.stringify(r))}')">
                                ${r.title} (${r.difficulty})
                            </a>
                        `).join('')}
                    </div>
                ` : ''}
                
                <div class="action-buttons">
                    <button class="button button-primary" onclick="applyFix('${vuln.id}', '${this._escapeHtml(rec.automaticFix)}')">
                        🔧 Apply Fix (~${rec.estimatedFixTime} min)
                    </button>
                    <button class="button button-secondary" onclick="learnMore('${this._escapeHtml(vuln.educationalContent || '')}')">
                        📖 Learn More
                    </button>
                </div>
            </div>
        `;
    }

    private _calculateStats() {
        const critical = this._vulnerabilities.filter(v => v.severity === 'critical').length;
        const high = this._vulnerabilities.filter(v => v.severity === 'high').length;
        const medium = this._vulnerabilities.filter(v => v.severity === 'medium').length;
        const low = this._vulnerabilities.filter(v => v.severity === 'low').length;
        
        const fixTime = this._recommendations.reduce((sum, rec) => sum + (rec?.estimatedFixTime || 0), 0);
        
        return { critical, high, medium, low, fixTime };
    }

    private _escapeHtml(text: string): string {
        const map: { [key: string]: string } = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
}