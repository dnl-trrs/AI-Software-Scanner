import * as vscode from 'vscode';

export class RecommendationPanel {
    public static currentPanel: RecommendationPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];

    public static createOrShow(extensionUri: vscode.Uri, recommendation: any) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        // If we already have a panel, show it
        if (RecommendationPanel.currentPanel) {
            RecommendationPanel.currentPanel._panel.reveal(column);
            RecommendationPanel.currentPanel._update(recommendation);
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

        RecommendationPanel.currentPanel = new RecommendationPanel(panel, extensionUri, recommendation);
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, recommendation: any) {
        this._panel = panel;
        this._extensionUri = extensionUri;

        // Set the webview's initial html content
        this._update(recommendation);

        // Listen for when the panel is disposed
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        // Handle messages from the webview
        this._panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'accept':
                        vscode.commands.executeCommand('ai-software-scanner.acceptRecommendation', message.data);
                        vscode.window.showInformationMessage('Recommendation accepted and applied!');
                        this._panel.dispose();
                        break;
                    case 'decline':
                        vscode.commands.executeCommand('ai-software-scanner.declineRecommendation', message.data);
                        vscode.window.showInformationMessage('Recommendation declined');
                        this._panel.dispose();
                        break;
                    case 'learnMore':
                        vscode.commands.executeCommand('ai-software-scanner.showEducation', message.data);
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

    private _update(recommendation: any) {
        this._panel.webview.html = this._getHtmlForWebview(this._panel.webview, recommendation);
    }

    private _getHtmlForWebview(webview: vscode.Webview, recommendation: any) {
        const nonce = this.getNonce();

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
                        max-width: 600px;
                        width: 90%;
                        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
                        animation: slideIn 0.3s ease-out;
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
                    }

                    .modal-title {
                        font-size: 18px;
                        font-weight: 600;
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
                    }

                    .section {
                        margin-bottom: 24px;
                    }

                    .section:last-child {
                        margin-bottom: 0;
                    }

                    .section-title {
                        font-size: 14px;
                        font-weight: 600;
                        margin-bottom: 8px;
                        color: var(--vscode-foreground);
                    }

                    .section-content {
                        font-size: 13px;
                        line-height: 1.5;
                        color: var(--vscode-descriptionForeground);
                    }

                    .code-block {
                        background: var(--vscode-textCodeBlock-background);
                        border: 1px solid var(--vscode-widget-border);
                        border-radius: 4px;
                        padding: 12px;
                        margin: 12px 0;
                        font-family: var(--vscode-editor-font-family);
                        font-size: 12px;
                        overflow-x: auto;
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
                        gap: 12px;
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
                        gap: 8px;
                        padding: 4px 8px;
                        background: var(--vscode-badge-background);
                        color: var(--vscode-badge-foreground);
                        border-radius: 4px;
                        font-size: 11px;
                        margin-top: 8px;
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
                        <span class="severity-badge severity-${recommendation.severity || 'medium'}">${recommendation.severity || 'medium'}</span>
                    </div>

                    <div class="modal-body">
                        <div class="section">
                            <div class="section-title">Issue Detected</div>
                            <div class="section-content">
                                ${recommendation.type || 'Security Issue'}: ${recommendation.message || 'Potential security vulnerability detected'}
                                <div class="location-info">
                                    📍 Line ${recommendation.line || '1'}, Column ${recommendation.column || '1'}
                                </div>
                            </div>
                        </div>

                        <div class="section">
                            <div class="section-title">Current Code</div>
                            <div class="code-block code-before">
                                <code>${recommendation.currentCode || 'public class HelloWorld {\\n    public static void main(String[] args) {\\n        System.out.println("Hello, World!");\\n    }\\n}'}</code>
                            </div>
                        </div>

                        <div class="section">
                            <div class="section-title">Recommended Fix</div>
                            <div class="section-content">
                                ${recommendation.suggestion || 'Apply security best practices to prevent potential vulnerabilities'}
                            </div>
                            <div class="code-block code-after">
                                <code>${recommendation.fixedCode || 'public class HelloWorld {\\n    public static void main(String[] args) {\\n        System.out.println("Hello, World!");\\n    }\\n}'}</code>
                            </div>
                        </div>

                        <div class="section">
                            <div class="section-title">Why This Matters</div>
                            <div class="section-content">
                                ${recommendation.explanation || 'This recommendation helps improve code security and follows industry best practices.'}
                                <br><br>
                                <a class="learn-more-link" id="learnMore">📚 Learn more about ${recommendation.type || 'this issue'}</a>
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
                            data: recommendation
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
                </script>
            </body>
            </html>`;
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